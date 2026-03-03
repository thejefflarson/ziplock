//! Sandbox integration tests.
//!
//! These tests apply a real macOS sandbox via sandbox_init() and verify
//! that file write restrictions and read denials are enforced.
//!
//! Each test forks a child process to apply the sandbox (sandbox_init is
//! irreversible and per-process, but cargo runs tests in threads).

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int};
use std::path::{Path, PathBuf};

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Returns true if we're already running inside a sandbox (nested sandbox_init is forbidden).
///
/// Uses a fork-based probe to avoid applying a sandbox to the calling process as a side effect
/// (sandbox_init is irreversible, so we must test it in a disposable child).
fn already_sandboxed() -> bool {
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

/// Run a closure in a forked child process with a sandbox applied.
/// Returns the child's exit code (0 = success, non-zero = test failure).
fn run_sandboxed<F: FnOnce()>(profile: &str, test_fn: F) -> i32 {
    use nix::sys::wait::WaitStatus;

    // Flush stdout/stderr before fork to avoid duplicated output
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            // In child: apply sandbox, run test, exit
            if let Err(e) = apply_sandbox(profile) {
                eprintln!("sandbox_init failed in child: {e}");
                std::process::exit(99);
            }
            // Run the test — if it panics, the child exits non-zero
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn));
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        nix::unistd::ForkResult::Parent { child } => {
            // In parent: wait for child
            match nix::sys::wait::waitpid(child, None).expect("waitpid failed") {
                WaitStatus::Exited(_, code) => code,
                other => {
                    eprintln!("child exited abnormally: {other:?}");
                    -1
                }
            }
        }
    }
}

#[test]
fn sandbox_blocks_writes_outside_allowed_paths() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-write"),
        Path::new(&home),
        &[],
        true,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-write").ok();

    let home_clone = home.clone();
    let code = run_sandboxed(&profile, move || {
        // Writing inside CWD should work
        let test_file = "/tmp/ziplock-test-write/sandbox-write-test.txt";
        std::fs::write(test_file, b"hello from sandbox").expect("write in CWD should succeed");
        std::fs::remove_file(test_file).ok();

        // Writing to ~/Library should fail (sensitive subtree protected even though HOME is broad-writable)
        let library_file = format!("{home_clone}/Library/sandbox-escape-test.txt");
        let result = std::fs::File::create(&library_file);
        assert!(result.is_err(), "should NOT be able to write to ~/Library");

        // Writing to /etc should fail
        let result = std::fs::File::create("/etc/sandbox-escape-test.txt");
        assert!(result.is_err(), "should NOT be able to write to /etc");
    });

    assert_eq!(code, 0, "sandbox write restriction test failed in child");
}

#[test]
fn sandbox_blocks_reads_to_library() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-readlib"),
        Path::new(&home),
        &[],
        true,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-readlib").ok();

    let library_path = format!("{home}/Library/Keychains");
    if !Path::new(&library_path).exists() {
        // Can't test this without the directory existing
        return;
    }

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(&library_path);
        assert!(
            result.is_err(),
            "should NOT be able to read ~/Library/Keychains"
        );
    });

    assert_eq!(code, 0, "sandbox read restriction test failed in child");
}

#[test]
fn sandbox_allows_reads_to_productivity_creds() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let ssh_dir = format!("{home}/.ssh");
    if !Path::new(&ssh_dir).exists() {
        return;
    }

    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-creds"),
        Path::new(&home),
        &[],
        true,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-creds").ok();

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(&ssh_dir);
        assert!(
            result.is_ok(),
            "should be able to read ~/.ssh: {:?}",
            result.err()
        );
    });

    assert_eq!(code, 0, "sandbox credential read test failed in child");
}

#[test]
fn sandbox_allows_framework_reads() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-fw"),
        Path::new(&home),
        &[],
        true,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-fw").ok();

    let fw_path = "/System/Library/Frameworks/CoreFoundation.framework";
    if !Path::new(fw_path).exists() {
        return;
    }

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::metadata(fw_path);
        assert!(
            result.is_ok(),
            "should be able to read system frameworks: {:?}",
            result.err()
        );
    });

    assert_eq!(code, 0, "sandbox framework read test failed in child");
}

#[test]
fn sandbox_extra_allow_path() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-extra"),
        Path::new(&home),
        &[PathBuf::from("/tmp/ziplock-extra-allowed")],
        true,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-extra").ok();
    std::fs::create_dir_all("/tmp/ziplock-extra-allowed").ok();

    let code = run_sandboxed(&profile, || {
        let test_file = "/tmp/ziplock-extra-allowed/extra-write-test.txt";
        std::fs::write(test_file, b"extra path allowed")
            .expect("write to --allow-path should succeed");
        std::fs::remove_file(test_file).ok();
    });

    assert_eq!(code, 0, "sandbox extra allow-path test failed in child");
}
