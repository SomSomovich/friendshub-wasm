//! WASM bindings for libsignal-protocol v0.103.1.
//!
//! Design:
//! - Each account (up to 5 per browser tab) owns an independent `Store`.
//!   Stores live in a thread-local `HashMap<account_id, Store>`.
//! - All public functions take `account_id` as their first argument.
//! - The public API is synchronous: libsignal futures are always ready.
//! - Persistence is JS-driven: call `snapshot(account_id)` to get a JSON
//!   blob, store it in IndexedDB, `restore(account_id, json)` on next load.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wasm_bindgen::JsValue;

pub mod api;
pub mod store;

/// Result alias used inside functions that produce JsValue errors.
pub(crate) type JsResult<T> = std::result::Result<T, JsValue>;

/// Minimal busy-loop executor for futures that are always ready.
///
/// Every libsignal future resolves on the first poll: there is no real IO,
/// no timers, no channels. Polling in a loop until Ready is enough and
/// avoids pulling in `futures`.
pub(crate) fn block_on<F: Future>(mut fut: F) -> F::Output {
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    fn raw_waker() -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    // SAFETY: the vtable does nothing, so the null data pointer is never
    // dereferenced.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is pinned to a stack slot that outlives the loop.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::hint::spin_loop(),
        }
    }
}

/// Wall clock on wasm32. `SystemTime::now()` panics in wasm32-unknown-unknown.
pub(crate) fn now() -> SystemTime {
    #[cfg(target_arch = "wasm32")]
    {
        UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
    }
}

pub(crate) fn now_unix() -> i64 {
    now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn now_millis() -> u64 {
    now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&format!("{}", e))
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}