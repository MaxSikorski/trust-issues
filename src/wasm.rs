//! The browser entry point (WebAssembly only, no JavaScript glue needed).
//!
//! `demo_run()` runs the five demo scenes against the real node code and
//! returns a pointer to the events as UTF-8 JSON; `demo_len()` gives its
//! length. The page reads the bytes straight out of the module's memory.

use std::sync::Mutex;

static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn out() -> std::sync::MutexGuard<'static, Vec<u8>> {
    OUT.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run the demo and return a pointer to its JSON events.
#[unsafe(no_mangle)]
pub extern "C" fn demo_run() -> *const u8 {
    let json = serde_json::to_vec(&crate::demo::run_blocking())
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}").into_bytes());
    let mut o = out();
    *o = json;
    o.as_ptr()
}

/// Length in bytes of the JSON from the last `demo_run()`.
#[unsafe(no_mangle)]
pub extern "C" fn demo_len() -> usize {
    out().len()
}
