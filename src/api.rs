//! Public `#[wasm_bindgen]` API. Thin wrappers over `store::*`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use libsignal_protocol::error::Result as SigResult;
use libsignal_protocol::{
    create_sender_key_distribution_message,
    group_decrypt as ls_group_decrypt,
    group_encrypt as ls_group_encrypt,
    kem,
    message_decrypt,
    message_encrypt,
    process_prekey_bundle,
    process_sender_key_distribution_message,
    CiphertextMessage,
    DeviceId,
    GenericSignedPreKey,
    IdentityKey,
    IdentityKeyPair,
    KeyPair,
    KyberPreKeyId,
    KyberPreKeyRecord,
    PreKeyBundle,
    PreKeyId,
    PreKeyRecord,
    PreKeySignalMessage,
    ProtocolAddress,
    PublicKey,
    SenderKeyDistributionMessage,
    SignalMessage,
    SignalProtocolError,
    SignedPreKeyId,
    SignedPreKeyRecord,
    Timestamp,
};
use wasm_bindgen::prelude::*;

use crate::store::{
    decode_identity_key_pair, drop_store, restore_inner, snapshot_inner, with_store,
};
use crate::{block_on, js_err, now, now_millis, JsResult};

// =============================================================================
// Lifecycle
// =============================================================================

/// Smoke test.
#[wasm_bindgen]
pub fn ping() -> String {
    "pong".to_string()
}

/// Generates a fresh identity key pair for `account_id`, registers the
/// local registration id, and returns the serialized key pair as hex
/// (65 bytes: 33 public + 32 private).
#[wasm_bindgen]
pub fn generate_identity(account_id: &str, registration_id: u32) -> JsResult<String> {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let blob = identity.serialize().to_vec();

    with_store(account_id, |s| {
        let mut inner = s.inner.borrow_mut();
        inner.identity = Some(identity);
        inner.registration_id = registration_id;
    });

    Ok(hex::encode(&blob))
}

/// Restores an identity key pair previously serialized with
/// `generate_identity`, or persisted via `snapshot`.
#[wasm_bindgen]
pub fn load_identity(account_id: &str, blob_hex: &str, registration_id: u32) -> JsResult<()> {
    let bytes = hex::decode(blob_hex).map_err(js_err)?;
    let identity = decode_identity_key_pair(&bytes).map_err(js_err)?;

    with_store(account_id, |s| {
        let mut inner = s.inner.borrow_mut();
        inner.identity = Some(identity);
        inner.registration_id = registration_id;
    });

    Ok(())
}

/// Returns the local public identity key as hex (33 bytes).
#[wasm_bindgen]
pub fn local_identity_public(account_id: &str) -> JsResult<String> {
    with_store(account_id, |s| {
        let inner = s.inner.borrow();
        let id = inner
            .identity
            .as_ref()
            .ok_or_else(|| js_err("no local identity"))?;
        Ok(hex::encode(id.identity_key().serialize()))
    })
}

/// Serializes the entire state for `account_id` to JSON.
#[wasm_bindgen]
pub fn snapshot(account_id: &str) -> JsResult<String> {
    with_store(account_id, |s| snapshot_inner(s))
}

/// Restores state from a blob produced by `snapshot`.
#[wasm_bindgen]
pub fn restore(account_id: &str, blob_json: &str) -> JsResult<()> {
    with_store(account_id, |s| restore_inner(s, blob_json))
}

/// Wipes all state for `account_id` and removes its slot.
#[wasm_bindgen]
pub fn reset(account_id: &str) {
    drop_store(account_id);
}

// =============================================================================
// Prekeys
// =============================================================================

/// Counts of available prekeys for `account_id`. JSON:
/// `{"one_time_available": N, "kyber_one_time_available": N,
///   "has_signed_prekey": bool, "has_kyber_last_resort": bool}`
#[wasm_bindgen]
pub fn prekey_counts(account_id: &str) -> JsResult<String> {
    with_store(account_id, |s| {
        let inner = s.inner.borrow();
        let otk = inner.pre_keys.len();
        // Kyber OTK and kyber last-resort share the same map. Last-resort
        // is identified by having a valid signature that is stored as its
        // own record; here we simply count all and report presence of at
        // least one. The JS layer treats the map as the OTK pool.
        let kyber = inner.kyber_pre_keys.len();
        let has_signed = !inner.signed_pre_keys.is_empty();
        let has_kyber_lr = !inner.kyber_pre_keys.is_empty();
        Ok(serde_json::to_string(&serde_json::json!({
            "one_time_available": otk,
            "kyber_one_time_available": kyber,
            "has_signed_prekey": has_signed,
            "has_kyber_last_resort": has_kyber_lr,
        }))
        .map_err(js_err)?)
    })
}

/// Generates `count` one-time prekeys on X25519 and Kyber, plus a fresh
/// signed prekey and a Kyber last-resort. Stores the private halves.
/// Returns JSON with the public halves, ready to POST to `/devices/me/prekeys`.
#[wasm_bindgen]
pub fn generate_prekeys(account_id: &str, count: usize) -> JsResult<String> {
    let mut rng = rand::rng();

    with_store(account_id, |s| {
        let (identity, next_start) = {
            let inner = s.inner.borrow();
            let identity = inner
                .identity
                .as_ref()
                .ok_or_else(|| js_err("no local identity"))?
                .clone();
            let next = inner
                .pre_keys
                .keys()
                .chain(inner.signed_pre_keys.keys())
                .chain(inner.kyber_pre_keys.keys())
                .max()
                .copied()
                .unwrap_or(0)
                + 1;
            (identity, next)
        };
        let mut next_id = next_start;

        // Signed prekey
        let signed_id = next_id;
        next_id += 1;
        let signed_kp = KeyPair::generate(&mut rng);
        let signed_pub = signed_kp.public_key.serialize();
        let signed_sig = identity
            .private_key()
            .calculate_signature(&signed_pub, &mut rng)
            .map_err(js_err)?;
        let signed_record = SignedPreKeyRecord::new(
            SignedPreKeyId::from(signed_id),
            Timestamp::from_epoch_millis(now_millis()),
            &signed_kp,
            &signed_sig,
        );

        // Kyber last resort
        let kyber_lr_id = next_id;
        next_id += 1;
        let kyber_lr = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            KyberPreKeyId::from(kyber_lr_id),
            identity.private_key(),
        )
        .map_err(js_err)?;
        let kyber_lr_pub = kyber_lr.public_key().map_err(js_err)?.serialize();
        let kyber_lr_sig = GenericSignedPreKey::signature(&kyber_lr).map_err(js_err)?;

        // X25519 OTKs
        let mut otk_json = Vec::with_capacity(count);
        let mut otk_records = Vec::with_capacity(count);
        for _ in 0..count {
            let kp = KeyPair::generate(&mut rng);
            let id = next_id;
            next_id += 1;
            otk_json.push(serde_json::json!({
                "id": id,
                "pub": hex::encode(kp.public_key.serialize()),
            }));
            otk_records.push((id, PreKeyRecord::new(PreKeyId::from(id), &kp)));
        }

        // Kyber OTKs
        let mut kyber_otk_json = Vec::with_capacity(count);
        let mut kyber_otk_records = Vec::with_capacity(count);
        for _ in 0..count {
            let id = next_id;
            next_id += 1;
            let r = KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                KyberPreKeyId::from(id),
                identity.private_key(),
            )
            .map_err(js_err)?;
            let pub_b = r.public_key().map_err(js_err)?.serialize();
            kyber_otk_json.push(serde_json::json!({
                "id": id,
                "pub": hex::encode(pub_b),
            }));
            kyber_otk_records.push((id, r));
        }

        {
            let mut inner = s.inner.borrow_mut();
            inner.signed_pre_keys.insert(signed_id, signed_record);
            inner.kyber_pre_keys.insert(kyber_lr_id, kyber_lr);
            for (id, r) in otk_records {
                inner.pre_keys.insert(id, r);
            }
            for (id, r) in kyber_otk_records {
                inner.kyber_pre_keys.insert(id, r);
            }
        }

        Ok(serde_json::to_string(&serde_json::json!({
            "signed_prekey": {
                "id": signed_id,
                "pub": hex::encode(&signed_pub),
                "sig": hex::encode(&signed_sig),
            },
            "kyber_last_resort": {
                "id": kyber_lr_id,
                "pub": hex::encode(&kyber_lr_pub),
                "sig": hex::encode(&kyber_lr_sig),
            },
            "one_time_prekeys": otk_json,
            "kyber_one_time_prekeys": kyber_otk_json,
        }))
        .map_err(js_err)?)
    })
}

// =============================================================================
// Sessions
// =============================================================================

#[wasm_bindgen]
pub fn establish_session(
    account_id: &str,
    peer_account_id: &str,
    peer_device_number: u32,
    local_device_number: u32,
    bundle_json: &str,
) -> JsResult<()> {
    let bundle_value: serde_json::Value = serde_json::from_str(bundle_json).map_err(js_err)?;
    let bundle = parse_bundle(&bundle_value).map_err(js_err)?;

    let remote = ProtocolAddress::new(
        peer_account_id.to_string(),
        DeviceId::try_from(peer_device_number).map_err(js_err)?,
    );
    let local = ProtocolAddress::new(
        account_id.to_string(),
        DeviceId::try_from(local_device_number).map_err(js_err)?,
    );

    with_store(account_id, |s| {
        let mut session_store = s.clone();
        let mut identity_store = s.clone();
        let mut rng = rand::rng();
        block_on(process_prekey_bundle(
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            &bundle,
            now(),
            &mut rng,
        ))
        .map_err(js_err)?;
        Ok(())
    })
}

#[wasm_bindgen]
pub fn encrypt(
    account_id: &str,
    peer_account_id: &str,
    peer_device_number: u32,
    local_device_number: u32,
    plaintext_hex: &str,
) -> JsResult<String> {
    let plaintext = hex::decode(plaintext_hex).map_err(js_err)?;

    let remote = ProtocolAddress::new(
        peer_account_id.to_string(),
        DeviceId::try_from(peer_device_number).map_err(js_err)?,
    );
    let local = ProtocolAddress::new(
        account_id.to_string(),
        DeviceId::try_from(local_device_number).map_err(js_err)?,
    );

    with_store(account_id, |s| {
        let mut session_store = s.clone();
        let mut identity_store = s.clone();
        let mut rng = rand::rng();
        let msg = block_on(message_encrypt(
            &plaintext,
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            now(),
            &mut rng,
        ))
        .map_err(js_err)?;
        let is_prekey = matches!(msg, CiphertextMessage::PreKeySignalMessage(_));
        Ok(serde_json::to_string(&serde_json::json!({
            "ciphertext_hex": hex::encode(msg.serialize()),
            "is_prekey_message": is_prekey,
        }))
        .map_err(js_err)?)
    })
}

#[wasm_bindgen]
pub fn decrypt(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    local_device_number: u32,
    ciphertext_hex: &str,
    is_prekey_message: bool,
) -> JsResult<String> {
    let bytes = hex::decode(ciphertext_hex).map_err(js_err)?;

    let ciphertext = if is_prekey_message {
        CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(&bytes[..]).map_err(js_err)?,
        )
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::try_from(&bytes[..]).map_err(js_err)?)
    };

    let remote = ProtocolAddress::new(
        sender_account_id.to_string(),
        DeviceId::try_from(sender_device_number).map_err(js_err)?,
    );
    let local = ProtocolAddress::new(
        account_id.to_string(),
        DeviceId::try_from(local_device_number).map_err(js_err)?,
    );

    with_store(account_id, |s| {
        let mut session_store = s.clone();
        let mut identity_store = s.clone();
        let mut pre_key_store = s.clone();
        let mut kyber_store = s.clone();
        let mut rng = rand::rng();
        let pt = block_on(message_decrypt(
            &ciphertext,
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            &mut pre_key_store,
            s,
            &mut kyber_store,
            &mut rng,
        ))
        .map_err(js_err)?;
        Ok(hex::encode(pt))
    })
}

// =============================================================================
// Group / sender keys
// =============================================================================

#[wasm_bindgen]
pub fn create_sender_key_distribution(
    account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
) -> JsResult<String> {
    let local = ProtocolAddress::new(
        account_id.to_string(),
        DeviceId::try_from(local_device_number).map_err(js_err)?,
    );

    with_store(account_id, |s| {
        let dist_id = {
            let mut inner = s.inner.borrow_mut();
            *inner
                .group_sender_keys
                .entry(conversation_id.to_string())
                .or_insert_with(uuid::Uuid::new_v4)
        };
        let mut sender_key_store = s.clone();
        let mut rng = rand::rng();
        let skdm = block_on(create_sender_key_distribution_message(
            &local,
            dist_id,
            &mut sender_key_store,
            &mut rng,
        ))
        .map_err(js_err)?;
        Ok(hex::encode(skdm.serialized()))
    })
}

#[wasm_bindgen]
pub fn process_sender_key_distribution(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    skdm_hex: &str,
) -> JsResult<()> {
    let bytes = hex::decode(skdm_hex).map_err(js_err)?;
    let skdm = SenderKeyDistributionMessage::try_from(&bytes[..]).map_err(js_err)?;
    let sender = ProtocolAddress::new(
        sender_account_id.to_string(),
        DeviceId::try_from(sender_device_number).map_err(js_err)?,
    );
    with_store(account_id, |s| {
        let mut store = s.clone();
        block_on(process_sender_key_distribution_message(
            &sender,
            &skdm,
            &mut store,
        ))
        .map_err(js_err)?;
        Ok(())
    })
}

#[wasm_bindgen]
pub fn group_encrypt(
    account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
    plaintext_hex: &str,
) -> JsResult<String> {
    let plaintext = hex::decode(plaintext_hex).map_err(js_err)?;
    let local = ProtocolAddress::new(
        account_id.to_string(),
        DeviceId::try_from(local_device_number).map_err(js_err)?,
    );
    with_store(account_id, |s| {
        let dist_id = {
            let inner = s.inner.borrow();
            *inner
                .group_sender_keys
                .get(conversation_id)
                .ok_or_else(|| js_err("no sender key distribution for this conversation"))?
        };
        let mut store = s.clone();
        let mut rng = rand::rng();
        let skm = block_on(ls_group_encrypt(
            &mut store,
            &local,
            dist_id,
            &plaintext,
            &mut rng,
        ))
        .map_err(js_err)?;
        Ok(hex::encode(skm.serialized()))
    })
}

#[wasm_bindgen]
pub fn group_decrypt(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    skm_hex: &str,
) -> JsResult<String> {
    let bytes = hex::decode(skm_hex).map_err(js_err)?;
    let sender = ProtocolAddress::new(
        sender_account_id.to_string(),
        DeviceId::try_from(sender_device_number).map_err(js_err)?,
    );
    with_store(account_id, |s| {
        let mut store = s.clone();
        let pt = block_on(ls_group_decrypt(&bytes, &mut store, &sender)).map_err(js_err)?;
        Ok(hex::encode(pt))
    })
}

// =============================================================================
// Identity change journal
// =============================================================================

/// Returns the pending identity-change entries for `account_id`, as a JSON
/// array. The caller is expected to show them to the user and then call
/// `clear_identity_changes`.
#[wasm_bindgen]
pub fn identity_changes(account_id: &str) -> JsResult<String> {
    with_store(account_id, |s| {
        let inner = s.inner.borrow();
        Ok(serde_json::to_string(&inner.identity_changes).map_err(js_err)?)
    })
}

#[wasm_bindgen]
pub fn clear_identity_changes(account_id: &str) {
    with_store(account_id, |s| {
        s.inner.borrow_mut().identity_changes.clear();
    });
}

// =============================================================================
// Attachments (chunked ChaCha20-Poly1305)
// =============================================================================

/// Generates a fresh symmetric key (32 bytes) and base nonce (4 bytes) for
/// one attachment. Returns JSON: `{"key_hex": "...", "base_nonce_hex": "..."}`.
#[wasm_bindgen]
pub fn generate_attachment_key() -> JsResult<String> {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    let mut base = [0u8; 4];
    rng.fill(&mut key);
    rng.fill(&mut base);
    Ok(serde_json::to_string(&serde_json::json!({
        "key_hex": hex::encode(key),
        "base_nonce_hex": hex::encode(base),
    }))
    .map_err(js_err)?)
}

fn attachment_nonce(base: &[u8; 4], index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(base);
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

fn decode_key_base(key_hex: &str, base_hex: &str) -> JsResult<([u8; 32], [u8; 4])> {
    let kb = hex::decode(key_hex).map_err(js_err)?;
    if kb.len() != 32 {
        return Err(js_err(format!("key is {} bytes, expected 32", kb.len())));
    }
    let bb = hex::decode(base_hex).map_err(js_err)?;
    if bb.len() != 4 {
        return Err(js_err(format!("base nonce is {} bytes, expected 4", bb.len())));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&kb);
    let mut base = [0u8; 4];
    base.copy_from_slice(&bb);
    Ok((key, base))
}

/// Seals one chunk: plaintext + 16-byte Poly1305 tag.
#[wasm_bindgen]
pub fn seal_chunk(
    key_hex: &str,
    base_hex: &str,
    chunk_index: u64,
    plaintext: &[u8],
) -> JsResult<Vec<u8>> {
    let (key, base) = decode_key_base(key_hex, base_hex)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_bytes = attachment_nonce(&base, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = chunk_index.to_be_bytes();
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| js_err(format!("seal failed: {e}")))
}

/// Opens one chunk. The sealed bytes must be exactly as stored.
#[wasm_bindgen]
pub fn open_chunk(
    key_hex: &str,
    base_hex: &str,
    chunk_index: u64,
    sealed: &[u8],
) -> JsResult<Vec<u8>> {
    if sealed.len() < 16 {
        return Err(js_err("sealed chunk shorter than tag"));
    }
    let (key, base) = decode_key_base(key_hex, base_hex)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_bytes = attachment_nonce(&base, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = chunk_index.to_be_bytes();
    cipher
        .decrypt(nonce, Payload { msg: sealed, aad: &aad })
        .map_err(|_| js_err("chunk failed authentication"))
}

// =============================================================================
// Prekey bundle parser
// =============================================================================

fn parse_bundle(v: &serde_json::Value) -> SigResult<PreKeyBundle> {
    let registration_id = v
        .get("registration_id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| SignalProtocolError::InvalidArgument("registration_id missing".into()))?
        as u32;
    let device_number = v
        .get("device_number")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| SignalProtocolError::InvalidArgument("device_number missing".into()))?
        as u32;
    let device_id = DeviceId::try_from(device_number)
        .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?;

    let identity_key_hex = v
        .get("identity_key_pub")
        .and_then(|x| x.as_str())
        .ok_or_else(|| SignalProtocolError::InvalidArgument("identity_key_pub missing".into()))?;
    let identity_key = IdentityKey::decode(
        &hex::decode(identity_key_hex)
            .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?,
    )?;

    let signed = v
        .get("signed_prekey")
        .ok_or_else(|| SignalProtocolError::InvalidArgument("signed_prekey missing".into()))?;
    let signed_id = signed
        .get("id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| SignalProtocolError::InvalidArgument("signed_prekey.id missing".into()))?
        as u32;
    let signed_pub = PublicKey::deserialize(
        &hex::decode(
            signed
                .get("pub")
                .and_then(|x| x.as_str())
                .ok_or_else(|| {
                    SignalProtocolError::InvalidArgument("signed_prekey.pub missing".into())
                })?,
        )
        .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?,
    )?;
    let signed_sig = hex::decode(
        signed
            .get("sig")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signed_prekey.sig missing".into())
            })?,
    )
    .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?;

    let kyber = v.get("kyber_last_resort").ok_or_else(|| {
        SignalProtocolError::InvalidArgument("kyber_last_resort missing".into())
    })?;
    let kyber_id = kyber
        .get("id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| SignalProtocolError::InvalidArgument("kyber.id missing".into()))?
        as u32;
    let kyber_pub = kem::PublicKey::deserialize(
        &hex::decode(
            kyber
                .get("pub")
                .and_then(|x| x.as_str())
                .ok_or_else(|| SignalProtocolError::InvalidArgument("kyber.pub missing".into()))?,
        )
        .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?,
    )?;
    let kyber_sig = hex::decode(
        kyber
            .get("sig")
            .and_then(|x| x.as_str())
            .ok_or_else(|| SignalProtocolError::InvalidArgument("kyber.sig missing".into()))?,
    )
    .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?;

    let otk = match v.get("one_time_prekey") {
        Some(o) if !o.is_null() => {
            let id = o
                .get("id")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| SignalProtocolError::InvalidArgument("otk.id missing".into()))?
                as u32;
            let pub_bytes = hex::decode(
                o.get("pub")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| {
                        SignalProtocolError::InvalidArgument("otk.pub missing".into())
                    })?,
            )
            .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Some((PreKeyId::from(id), PublicKey::deserialize(&pub_bytes)?))
        }
        _ => None,
    };

    PreKeyBundle::new(
        registration_id,
        device_id,
        otk,
        SignedPreKeyId::from(signed_id),
        signed_pub,
        signed_sig,
        KyberPreKeyId::from(kyber_id),
        kyber_pub,
        kyber_sig,
        identity_key,
    )
}