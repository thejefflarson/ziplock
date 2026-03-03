//! End-to-end integration tests.
//!
//! These verify sandbox enforcement with real sandbox_init() calls.
//! Each test forks a child process (sandbox_init is irreversible and per-process).
//!
//! Note: sandbox + proxy combined testing via fork is not feasible because
//! tokio's kqueue FDs can't survive fork(). The sandbox tests and proxy tests
//! independently verify their layers, which compose at runtime.

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int};
use std::io::Write;
use std::path::Path;

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

fn apply_sandbox(profile: &str) -> Result<(), String> {
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

/// Test: sandboxed process can write inside CWD, cannot write outside it.
#[test]
fn sandboxed_write_cwd_only() {
    let home = std::env::var("HOME").unwrap();
    let cwd = Path::new("/tmp/ziplock-e2e-write");
    std::fs::create_dir_all(cwd).ok();

    let profile = ziplock::sandbox::generate_profile(cwd, Path::new(&home), &[], true).unwrap();

    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    let home_clone = home.clone();
    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            apply_sandbox(&profile).unwrap_or_else(|e| {
                eprintln!("sandbox_init failed: {e}");
                std::process::exit(99);
            });

            // Write inside CWD — should work
            let test_file = "/tmp/ziplock-e2e-write/write-test.txt";
            std::fs::write(test_file, b"sandbox allows this")
                .expect("write inside CWD should succeed");
            let contents = std::fs::read_to_string(test_file).unwrap();
            assert_eq!(contents, "sandbox allows this");
            std::fs::remove_file(test_file).ok();

            // Write outside CWD — should fail
            let bad = format!("{home_clone}/ziplock-e2e-escape.txt");
            assert!(
                std::fs::File::create(&bad).is_err(),
                "write to HOME should be blocked"
            );

            assert!(
                std::fs::File::create("/etc/ziplock-e2e-test").is_err(),
                "write to /etc should be blocked"
            );

            std::process::exit(0);
        }
        nix::unistd::ForkResult::Parent { child } => {
            use nix::sys::wait::WaitStatus;
            match nix::sys::wait::waitpid(child, None).expect("waitpid failed") {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, code) => panic!("child exited with code {code}"),
                other => panic!("child exited abnormally: {other:?}"),
            }
        }
    }
}

/// Test: sandboxed process can read ~/.ssh but not ~/Library/Keychains.
#[test]
fn sandboxed_read_permissions() {
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-e2e-reads"),
        Path::new(&home),
        &[],
        true,
    )
    .unwrap();
    std::fs::create_dir_all("/tmp/ziplock-e2e-reads").ok();

    let home_clone = home.clone();
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            apply_sandbox(&profile).unwrap_or_else(|e| {
                eprintln!("sandbox_init failed: {e}");
                std::process::exit(99);
            });

            // ~/.ssh should be readable (productivity credentials)
            let ssh_dir = format!("{home_clone}/.ssh");
            if Path::new(&ssh_dir).exists() {
                assert!(
                    std::fs::read_dir(&ssh_dir).is_ok(),
                    "should be able to read ~/.ssh"
                );
            }

            // ~/Library/Keychains should be blocked
            let keychains = format!("{home_clone}/Library/Keychains");
            if Path::new(&keychains).exists() {
                assert!(
                    std::fs::read_dir(&keychains).is_err(),
                    "should NOT be able to read ~/Library/Keychains"
                );
            }

            // /System/Library/Frameworks should be readable (carve-out)
            let fw = "/System/Library/Frameworks/CoreFoundation.framework";
            if Path::new(fw).exists() {
                assert!(
                    std::fs::metadata(fw).is_ok(),
                    "should be able to read system frameworks"
                );
            }

            std::process::exit(0);
        }
        nix::unistd::ForkResult::Parent { child } => {
            use nix::sys::wait::WaitStatus;
            match nix::sys::wait::waitpid(child, None).expect("waitpid failed") {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, code) => panic!("child exited with code {code}"),
                other => panic!("child exited abnormally: {other:?}"),
            }
        }
    }
}
