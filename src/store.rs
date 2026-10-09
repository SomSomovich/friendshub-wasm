//! Per-account Signal state. Each `account_id` gets its own `Store`,
//! stashed in a thread-local `HashMap`. Stores are cheap to clone (`Rc`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use async_trait::async_trait;
use libsignal_protocol::error::Result as SigResult;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId,
    PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SenderKeyRecord,
    SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{now_unix, JsResult};

/// One row in the identity-change journal.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IdentityChangeEntry {
    pub account_id: String,
    pub device_number: u32,
    pub old_key_hex: String,
    pub new_key_hex: String,
    pub changed_at: i64,
}

#[derive(Default)]
pub(crate) struct StoreInner {
    pub identity: Option<IdentityKeyPair>,
    pub registration_id: u32,
    pub peer_identities: HashMap<(String, u32), IdentityKey>,
    pub pre_keys: HashMap<u32, PreKeyRecord>,
    pub signed_pre_keys: HashMap<u32, SignedPreKeyRecord>,
    pub kyber_pre_keys: HashMap<u32, KyberPreKeyRecord>,
    pub sessions: HashMap<(String, u32), SessionRecord>,
    pub sender_keys: HashMap<(String, u32, Uuid), SenderKeyRecord>,
    pub group_sender_keys: HashMap<String, Uuid>,
    pub identity_changes: Vec<IdentityChangeEntry>,
}

#[derive(Clone)]
pub(crate) struct Store {
    pub inner: Rc<RefCell<StoreInner>>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(StoreInner::default())),
        }
    }
}

thread_local! {
    static STORES: RefCell<HashMap<String, Store>> = RefCell::new(HashMap::new());
}

pub(crate) fn with_store<F, R>(account_id: &str, f: F) -> R
where
    F: FnOnce(&Store) -> R,
{
    STORES.with(|m| {
        let store = {
            let mut map = m.borrow_mut();
            map.entry(account_id.to_string())
                .or_insert_with(Store::new)
                .clone()
        };
        f(&store)
    })
}

pub(crate) fn drop_store(account_id: &str) {
    STORES.with(|m| {
        m.borrow_mut().remove(account_id);
    });
}

fn addr_key(addr: &ProtocolAddress) -> (String, u32) {
    (addr.name().to_string(), u32::from(addr.device_id()))
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

#[async_trait(?Send)]
impl IdentityKeyStore for Store {
    async fn get_identity_key_pair(&self) -> SigResult<IdentityKeyPair> {
        self.inner
            .borrow()
            .identity
            .clone()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("no local identity".into()))
    }

    async fn get_local_registration_id(&self) -> SigResult<u32> {
        Ok(self.inner.borrow().registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SigResult<IdentityChange> {
        let key = addr_key(address);
        let mut inner = self.inner.borrow_mut();
        let changed = match inner.peer_identities.get(&key) {
            Some(existing) => existing != identity,
            None => true,
        };
        if changed && let Some(old) = inner.peer_identities.get(&key).cloned() {
            inner.identity_changes.push(IdentityChangeEntry {
                account_id: key.0.clone(),
                device_number: key.1,
                old_key_hex: hex::encode(old.serialize()),
                new_key_hex: hex::encode(identity.serialize()),
                changed_at: now_unix(),
            });
        }
        inner.peer_identities.insert(key, identity.clone());
        Ok(if changed {
            IdentityChange::ReplacedExisting
        } else {
            IdentityChange::NewOrUnchanged
        })
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> SigResult<bool> {
        Ok(true)
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SigResult<Option<IdentityKey>> {
        let key = addr_key(address);
        Ok(self.inner.borrow().peer_identities.get(&key).cloned())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for Store {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> SigResult<PreKeyRecord> {
        let id = u32::from(prekey_id);
        self.inner
            .borrow()
            .pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("prekey {id} not found"))
            })
    }
    async fn save_pre_key(&mut self, id: PreKeyId, r: &PreKeyRecord) -> SigResult<()> {
        self.inner.borrow_mut().pre_keys.insert(u32::from(id), r.clone());
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> SigResult<()> {
        self.inner.borrow_mut().pre_keys.remove(&u32::from(id));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for Store {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SigResult<SignedPreKeyRecord> {
        let id = u32::from(id);
        self.inner
            .borrow()
            .signed_pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("signed prekey {id} not found"))
            })
    }
    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        r: &SignedPreKeyRecord,
    ) -> SigResult<()> {
        self.inner
            .borrow_mut()
            .signed_pre_keys
            .insert(u32::from(id), r.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for Store {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SigResult<KyberPreKeyRecord> {
        let id = u32::from(id);
        self.inner
            .borrow()
            .kyber_pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("kyber prekey {id} not found"))
            })
    }
    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        r: &KyberPreKeyRecord,
    ) -> SigResult<()> {
        self.inner
            .borrow_mut()
            .kyber_pre_keys
            .insert(u32::from(id), r.clone());
        Ok(())
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        _id: KyberPreKeyId,
        _ec: SignedPreKeyId,
        _base: &PublicKey,
    ) -> SigResult<()> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for Store {
    async fn load_session(&self, a: &ProtocolAddress) -> SigResult<Option<SessionRecord>> {
        Ok(self.inner.borrow().sessions.get(&addr_key(a)).cloned())
    }
    async fn store_session(&mut self, a: &ProtocolAddress, r: &SessionRecord) -> SigResult<()> {
        self.inner.borrow_mut().sessions.insert(addr_key(a), r.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for Store {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        dist: Uuid,
        r: &SenderKeyRecord,
    ) -> SigResult<()> {
        let (n, d) = addr_key(sender);
        self.inner
            .borrow_mut()
            .sender_keys
            .insert((n, d, dist), r.clone());
        Ok(())
    }
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        dist: Uuid,
    ) -> SigResult<Option<SenderKeyRecord>> {
        let (n, d) = addr_key(sender);
        Ok(self.inner.borrow().sender_keys.get(&(n, d, dist)).cloned())
    }
}

// ---------------------------------------------------------------------------
// Snapshot / restore
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub identity: Option<String>,
    pub registration_id: u32,
    pub peer_identities: Vec<(String, u32, String)>,
    pub pre_keys: Vec<(u32, String)>,
    pub signed_pre_keys: Vec<(u32, String)>,
    pub kyber_pre_keys: Vec<(u32, String)>,
    pub sessions: Vec<(String, u32, String)>,
    pub sender_keys: Vec<(String, u32, String, String)>,
    pub group_sender_keys: Vec<(String, String)>,
    pub identity_changes: Vec<IdentityChangeEntry>,
}

pub(crate) fn snapshot_inner(store: &Store) -> JsResult<String> {
    let inner = store.inner.borrow();

    let peer_identities = inner
        .peer_identities
        .iter()
        .map(|((a, d), k)| (a.clone(), *d, hex::encode(k.serialize())))
        .collect();

    let pre_keys: Vec<(u32, String)> = inner
        .pre_keys
        .iter()
        .map(|(id, r)| {
            let b = r.serialize().map_err(crate::js_err)?;
            Ok((*id, hex::encode(b)))
        })
        .collect::<JsResult<_>>()?;

    let signed_pre_keys: Vec<(u32, String)> = inner
        .signed_pre_keys
        .iter()
        .map(|(id, r)| {
            let b = GenericSignedPreKey::serialize(r).map_err(crate::js_err)?;
            Ok((*id, hex::encode(b)))
        })
        .collect::<JsResult<_>>()?;

    let kyber_pre_keys: Vec<(u32, String)> = inner
        .kyber_pre_keys
        .iter()
        .map(|(id, r)| {
            let b = GenericSignedPreKey::serialize(r).map_err(crate::js_err)?;
            Ok((*id, hex::encode(b)))
        })
        .collect::<JsResult<_>>()?;

    let sessions: Vec<(String, u32, String)> = inner
        .sessions
        .iter()
        .map(|((a, d), r)| {
            let b = r.serialize().map_err(crate::js_err)?;
            Ok((a.clone(), *d, hex::encode(b)))
        })
        .collect::<JsResult<_>>()?;

    let sender_keys: Vec<(String, u32, String, String)> = inner
        .sender_keys
        .iter()
        .map(|((a, d, u), r)| {
            let b = r.serialize().map_err(crate::js_err)?;
            Ok((a.clone(), *d, u.to_string(), hex::encode(b)))
        })
        .collect::<JsResult<_>>()?;

    let group_sender_keys = inner
        .group_sender_keys
        .iter()
        .map(|(c, u)| (c.clone(), u.to_string()))
        .collect();

    let snap = Snapshot {
        identity: inner
            .identity
            .as_ref()
            .map(|id| hex::encode(id.serialize().to_vec())),
        registration_id: inner.registration_id,
        peer_identities,
        pre_keys,
        signed_pre_keys,
        kyber_pre_keys,
        sessions,
        sender_keys,
        group_sender_keys,
        identity_changes: inner.identity_changes.clone(),
    };

    Ok(serde_json::to_string(&snap).map_err(crate::js_err)?)
}

pub(crate) fn restore_inner(store: &Store, blob: &str) -> JsResult<()> {
    let snap: Snapshot = serde_json::from_str(blob).map_err(crate::js_err)?;

    let mut inner = store.inner.borrow_mut();
    *inner = StoreInner::default();

    if let Some(h) = &snap.identity {
        let bytes = hex::decode(h).map_err(crate::js_err)?;
        inner.identity = Some(decode_identity_key_pair(&bytes).map_err(crate::js_err)?);
    }
    inner.registration_id = snap.registration_id;

    for (a, d, h) in snap.peer_identities {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        inner
            .peer_identities
            .insert((a, d), IdentityKey::decode(&b).map_err(crate::js_err)?);
    }
    for (id, h) in snap.pre_keys {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        inner
            .pre_keys
            .insert(id, PreKeyRecord::deserialize(&b).map_err(crate::js_err)?);
    }
    for (id, h) in snap.signed_pre_keys {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        inner.signed_pre_keys.insert(
            id,
            <SignedPreKeyRecord as GenericSignedPreKey>::deserialize(&b).map_err(crate::js_err)?,
        );
    }
    for (id, h) in snap.kyber_pre_keys {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        inner.kyber_pre_keys.insert(
            id,
            <KyberPreKeyRecord as GenericSignedPreKey>::deserialize(&b).map_err(crate::js_err)?,
        );
    }
    for (a, d, h) in snap.sessions {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        inner
            .sessions
            .insert((a, d), SessionRecord::deserialize(&b).map_err(crate::js_err)?);
    }
    for (a, d, u, h) in snap.sender_keys {
        let b = hex::decode(&h).map_err(crate::js_err)?;
        let uuid = Uuid::parse_str(&u).map_err(crate::js_err)?;
        inner
            .sender_keys
            .insert((a, d, uuid), SenderKeyRecord::deserialize(&b).map_err(crate::js_err)?);
    }
    for (c, u) in snap.group_sender_keys {
        inner
            .group_sender_keys
            .insert(c, Uuid::parse_str(&u).map_err(crate::js_err)?);
    }
    inner.identity_changes = snap.identity_changes;

    Ok(())
}

// ---------------------------------------------------------------------------
// Identity key pair helpers
// ---------------------------------------------------------------------------

pub(crate) fn decode_identity_key_pair(blob: &[u8]) -> SigResult<IdentityKeyPair> {
    // Round-trips with `IdentityKeyPair::serialize()`, which produces
    // protobuf-encoded bytes (69 bytes for an X25519 identity in v0.103.1).
    // The previous 65-byte raw assumption was wrong. The native
    // friendshub-core has the same mismatch and needs the same fix.
    IdentityKeyPair::try_from(blob)
        .map_err(|e| SignalProtocolError::InvalidArgument(format!("identity key pair: {e}")))
}