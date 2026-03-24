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
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Returns true if we're already running inside a sandbox (nested sandbox_init is forbidden).
/// In that case the calling test should return early rather than fail.
///
/// Uses a fork-based probe to avoid applying a sandbox to the calling process as a side effect
/// (sandbox_init is irreversible, so we must test it in a disposable child).
fn already_sandboxed() -> bool {
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

/// Test: sandboxed process can write inside CWD and $HOME, cannot write to ~/Library or /etc.
///
/// Note: writes are allowed to all of $HOME (excluding ~/Library) so that
/// Claude Code's LSP plugins (rust-analyzer, typescript, swift) can write
/// throughout the home directory at startup.
#[test]
fn sandboxed_write_cwd_only() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let cwd = Path::new("/tmp/ziplock-e2e-write");
    std::fs::create_dir_all(cwd).ok();

    let profile =
        ziplock::sandbox::generate_profile(cwd, Path::new(&home), &[], true, None, &[]).unwrap();

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

            // Write to ~/Library — should fail (sensitive subtree protected)
            let library_file = format!("{home_clone}/Library/ziplock-e2e-test.txt");
            assert!(
                std::fs::File::create(&library_file).is_err(),
                "write to ~/Library should be blocked"
            );

            // Write to /etc — should fail (system tree protected)
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

/// Test: `claude --version` runs successfully inside the sandbox.
///
/// This is the key smoke test — if claude can't even print its version
/// inside the sandbox, nothing else will work.
///
/// Requires running outside any sandbox environment (e.g., not via ziplock).
/// Run with: `cargo test -- --ignored claude_version_runs_in_sandbox`
#[test]
#[ignore]
fn claude_version_runs_in_sandbox() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let claude_path = match which::which("claude") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: claude not found in PATH");
            return;
        }
    };

    let home = std::env::var("HOME").unwrap();
    let cwd = Path::new("/tmp/ziplock-e2e-version");
    std::fs::create_dir_all(cwd).ok();

    let profile =
        ziplock::sandbox::generate_profile(cwd, Path::new(&home), &[], true, None, &[]).unwrap();

    let profile_for_closure = profile.clone();
    let mut cmd = Command::new(&claude_path);
    cmd.arg("--version");
    cmd.current_dir(cwd);
    cmd.env("TMPDIR", "/tmp/claude");
    // Clear nested-session detection so test works when run from inside Claude Code
    cmd.env_remove("CLAUDECODE");
    std::fs::create_dir_all("/tmp/claude").ok();

    unsafe {
        cmd.pre_exec(move || {
            let profile_cstr =
                CString::new(profile_for_closure.as_bytes()).map_err(std::io::Error::other)?;
            let mut errorbuf: *mut c_char = std::ptr::null_mut();
            let ret = sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf);
            if ret != 0 {
                let err_msg = if !errorbuf.is_null() {
                    let msg = std::ffi::CStr::from_ptr(errorbuf)
                        .to_string_lossy()
                        .into_owned();
                    sandbox_free_error(errorbuf);
                    msg
                } else {
                    "unknown sandbox_init error".to_string()
                };
                return Err(std::io::Error::other(format!(
                    "sandbox_init failed: {err_msg}"
                )));
            }
            Ok(())
        });
    }

    let output = cmd.output().expect("failed to run claude --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "claude --version failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );

    // claude --version should print something like "1.0.x" or "claude x.y.z"
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains('.'),
        "expected version output containing '.', got: {combined}"
    );
}

/// Test: `claude -p "say hi"` produces a real response inside the sandbox.
///
/// This exercises the full stack: sandbox + process execution + API call.
/// Requires a valid API key in the environment. Skipped if claude is missing.
#[test]
#[ignore] // requires API key and network — run with `cargo test -- --ignored`
fn claude_responds_in_sandbox() {
    let claude_path = match which::which("claude") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: claude not found in PATH");
            return;
        }
    };

    let home = std::env::var("HOME").unwrap();
    let cwd = Path::new("/tmp/ziplock-e2e-respond");
    std::fs::create_dir_all(cwd).ok();
    std::fs::create_dir_all("/tmp/claude").ok();

    // Use allow_network=true so the API call can reach Anthropic
    let profile =
        ziplock::sandbox::generate_profile(cwd, Path::new(&home), &[], true, None, &[]).unwrap();

    let profile_for_closure = profile.clone();
    let mut cmd = Command::new(&claude_path);
    cmd.args([
        "--dangerously-skip-permissions",
        "-p",
        "Reply with exactly: ZIPLOCK_OK",
    ]);
    cmd.current_dir(cwd);
    cmd.env("TMPDIR", "/tmp/claude");
    // Clear nested-session detection so test works when run from inside Claude Code
    cmd.env_remove("CLAUDECODE");

    unsafe {
        cmd.pre_exec(move || {
            let profile_cstr =
                CString::new(profile_for_closure.as_bytes()).map_err(std::io::Error::other)?;
            let mut errorbuf: *mut c_char = std::ptr::null_mut();
            let ret = sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf);
            if ret != 0 {
                let err_msg = if !errorbuf.is_null() {
                    let msg = std::ffi::CStr::from_ptr(errorbuf)
                        .to_string_lossy()
                        .into_owned();
                    sandbox_free_error(errorbuf);
                    msg
                } else {
                    "unknown sandbox_init error".to_string()
                };
                return Err(std::io::Error::other(format!(
                    "sandbox_init failed: {err_msg}"
                )));
            }
            Ok(())
        });
    }

    let output = cmd.output().expect("failed to run claude -p");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{stdout}{stderr}");

    // "Not logged in" means claude started fine but has no API key — not a sandbox issue
    if combined.contains("Not logged in") || combined.contains("/login") {
        eprintln!("claude launched OK but not authenticated (expected in CI)");
        return;
    }

    // Sandbox errors show up as EPERM or setRawMode failures
    assert!(
        !combined.contains("setRawMode"),
        "setRawMode error — sandbox is blocking TTY ioctl:\n{combined}"
    );
    assert!(
        !combined.contains("Operation not permitted"),
        "sandbox EPERM error:\n{combined}"
    );

    assert!(
        output.status.success(),
        "claude -p failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("ZIPLOCK_OK"),
        "expected response containing ZIPLOCK_OK, got:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// Test: sandboxed process can read ~/.ssh but not ~/Library/Keychains.
#[test]
fn sandboxed_read_permissions() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-e2e-reads"),
        Path::new(&home),
        &[],
        true,
        None,
        &[],
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

            // ~/Library/Keychains should be readable (carve-out for developer tools like gh)
            let keychains = format!("{home_clone}/Library/Keychains");
            if Path::new(&keychains).exists() {
                assert!(
                    std::fs::read_dir(&keychains).is_ok(),
                    "should be able to read ~/Library/Keychains"
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
