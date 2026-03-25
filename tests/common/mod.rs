#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Returns true if the current process is already running inside a sandbox.
///
/// Uses a fork-based probe because sandbox_init is irreversible — applying it
/// to the test process as a side effect would break subsequent sandbox tests.
pub fn already_sandboxed() -> bool {
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            let profile = c"(version 1)(allow default)";
            let mut errorbuf: *mut c_char = std::ptr::null_mut();
            let ret = unsafe { sandbox_init(profile.as_ptr(), 0, &mut errorbuf) };
            if ret != 0 {
                if !errorbuf.is_null() {
                    unsafe { sandbox_free_error(errorbuf) };
                }
                std::process::exit(1); // nested sandbox detected
            }
            std::process::exit(0); // not sandboxed
        }
        nix::unistd::ForkResult::Parent { child } => !matches!(
            nix::sys::wait::waitpid(child, None).expect("waitpid failed"),
            nix::sys::wait::WaitStatus::Exited(_, 0)
        ),
    }
}

/// Apply a sandbox profile to the current process (irreversible).
pub fn apply_sandbox(profile: &str) -> Result<(), String> {
    let profile_cstr = CString::new(profile).map_err(|e| e.to_string())?;
    let mut errorbuf: *mut c_char = std::ptr::null_mut();
    let ret = unsafe { sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf) };
    if ret != 0 {
        let msg = if !errorbuf.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(errorbuf) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(errorbuf) };
            s
        } else {
            "unknown error".to_string()
        };
        return Err(msg);
    }
    Ok(())
}
