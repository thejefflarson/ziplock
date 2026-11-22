//! End-to-end integration tests.
//!
//! These verify sandbox enforcement with real sandbox_init() calls.
//! Each test forks a child process (sandbox_init is irreversible and per-process).
//!
//! Note: sandbox + proxy combined testing via fork is not feasible because
//! tokio's kqueue FDs can't survive fork(). The sandbox tests and proxy tests
//! independently verify their layers, which compose at runtime.

#![cfg(target_os = "macos")]

mod common;

use std::ffi::{CString, c_char, c_int};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

// Still needed for the cmd.pre_exec closures in claude_version_runs_in_sandbox
// and claude_responds_in_sandbox, which call sandbox_init directly after fork.
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
    /// APFS copy-on-write clone (`clonefile(2)`); used to probe whether the sandbox
    /// denies cloning a read-denied ~/Library source.
    fn clonefile(src: *const c_char, dst: *const c_char, flags: u32) -> c_int;
}

/// Test: sandboxed process can write inside CWD and $HOME, cannot write to ~/Library or /etc.
///
/// Note: writes are allowed to all of $HOME (excluding ~/Library) so that
/// Claude Code's LSP plugins (rust-analyzer, typescript, swift) can write
/// throughout the home directory at startup.
#[test]
fn sandboxed_write_cwd_only() {
    if common::already_sandboxed() {
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
            common::apply_sandbox(&profile).unwrap_or_else(|e| {
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
    if common::already_sandboxed() {
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
    if common::already_sandboxed() {
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
            common::apply_sandbox(&profile).unwrap_or_else(|e| {
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

/// Walk ~/Library for a regular file the sandbox profile denies reading (outside the
/// read carve-outs) that is still readable by this unsandboxed test process, to use as a
/// clone/hard-link source. Returns the first match within a bounded depth, or None.
fn find_read_denied_library_file(home: &Path) -> Option<String> {
    // Top-level ~/Library names that ARE read carve-outs in the profile — skip them so the
    // source is genuinely read-denied. "Application Support" is skipped wholesale because it
    // has carved subdirs (go, k9s, Ollama, …); any denied file elsewhere serves the probe.
    const CARVED: &[&str] = &[
        "Preferences",
        "Caches",
        "Keychains",
        "Developer",
        "org.swift.swiftpm",
        "Security",
        "helm",
        "Jupyter",
        "Group Containers",
        "Application Support",
    ];
    fn walk(dir: &Path, depth: u32) -> Option<String> {
        if depth == 0 {
            return None;
        }
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            let ft = entry.file_type().ok()?;
            // Readable by this process (not TCC-blocked / not a dangling link)?
            if ft.is_file() && std::fs::File::open(&path).is_ok() {
                return Some(path.to_string_lossy().into_owned());
            } else if ft.is_dir()
                && let Some(found) = walk(&path, depth - 1)
            {
                return Some(found);
            }
        }
        None
    }
    let library = home.join("Library");
    for entry in std::fs::read_dir(&library).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if CARVED.contains(&name.as_str()) {
            continue;
        }
        if entry.file_type().ok()?.is_dir()
            && let Some(found) = walk(&entry.path(), 3)
        {
            return Some(found);
        }
    }
    None
}

/// Regression: the ~/Library *read* deny must not be bypassable by hard-linking or
/// cloning (`clonefile`) a ~/Library file to a readable path and reading the copy.
/// `file-clone`/`file-link` are allowed broadly under $HOME; this verifies the kernel
/// also denies the operation when the *source* is a read-denied ~/Library path, so a
/// sandboxed process cannot launder browser/Messages/other-app secrets out of ~/Library.
#[test]
fn sandbox_blocks_library_read_via_hardlink_and_clone() {
    if common::already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();

    // Find a readable-outside regular file under a ~/Library subtree that our profile
    // *denies* reading — i.e. not one of the read carve-outs (Preferences, Caches,
    // Keychains, Developer, …) and not a TCC-protected dir the test can't enumerate
    // anyway. This mirrors the finding's real targets (browser/Messages/other-app data).
    // Without one the test can't conclude — skip.
    let source = find_read_denied_library_file(Path::new(&home));
    let Some(source) = source else {
        eprintln!("skipping: no readable, read-denied ~/Library file available as a source");
        return;
    };

    let cwd = Path::new("/tmp/ziplock-e2e-linkbypass");
    std::fs::create_dir_all(cwd).ok();
    let profile =
        ziplock::sandbox::generate_profile(cwd, Path::new(&home), &[], true, None, &[]).unwrap();

    let dst_link = cwd.join("hardlink_copy");
    let dst_clone = cwd.join("clone_copy");
    std::fs::remove_file(&dst_link).ok();
    std::fs::remove_file(&dst_clone).ok();

    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    let (src_c, link_c, clone_c) = (
        source.clone(),
        dst_link.to_string_lossy().into_owned(),
        dst_clone.to_string_lossy().into_owned(),
    );

    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            common::apply_sandbox(&profile).unwrap_or_else(|e| {
                eprintln!("sandbox_init failed: {e}");
                std::process::exit(99);
            });

            // (bit0) Direct read of the ~/Library source must be denied — sanity that the
            // control under test is actually active for this source.
            let direct_denied = std::fs::read(&src_c).is_err();

            // (bit1) hard_link succeeded; (bit2) and the copy's contents were disclosed.
            let hl = std::fs::hard_link(&src_c, &link_c);
            let hl_ok = hl.is_ok();
            let hl_disclosed = hl_ok
                && std::fs::read(&link_c)
                    .map(|b| !b.is_empty())
                    .unwrap_or(false);

            // (bit3) clonefile succeeded; (bit4) and the copy's contents were disclosed.
            let src_cstr = CString::new(src_c.as_bytes()).unwrap();
            let clone_cstr = CString::new(clone_c.as_bytes()).unwrap();
            let cl_ret = unsafe { clonefile(src_cstr.as_ptr(), clone_cstr.as_ptr(), 0) };
            let cl_ok = cl_ret == 0;
            let cl_disclosed = cl_ok
                && std::fs::read(&clone_c)
                    .map(|b| !b.is_empty())
                    .unwrap_or(false);

            std::fs::remove_file(&link_c).ok();
            std::fs::remove_file(&clone_c).ok();

            let code = (direct_denied as i32)
                | ((hl_ok as i32) << 1)
                | ((hl_disclosed as i32) << 2)
                | ((cl_ok as i32) << 3)
                | ((cl_disclosed as i32) << 4);
            std::process::exit(code);
        }
        nix::unistd::ForkResult::Parent { child } => {
            use nix::sys::wait::WaitStatus;
            std::fs::remove_file(&dst_link).ok();
            std::fs::remove_file(&dst_clone).ok();
            let code = match nix::sys::wait::waitpid(child, None).expect("waitpid failed") {
                WaitStatus::Exited(_, 99) => panic!("sandbox_init failed in child"),
                WaitStatus::Exited(_, c) => c,
                other => panic!("child exited abnormally: {other:?}"),
            };
            eprintln!(
                "probe source={source} outcome_bits={code:#07b} (b0 direct-denied, b1 hardlink-ok, b2 hl-disclosed, b3 clone-ok, b4 clone-disclosed)"
            );
            if code & 0b1 == 0 {
                eprintln!(
                    "skipping: source was readable under the sandbox (carve-out?); inconclusive"
                );
                return;
            }
            let hl_disclosed = code & 0b100 != 0;
            let cl_disclosed = code & 0b10000 != 0;
            assert!(
                !hl_disclosed,
                "SECURITY: ~/Library file contents disclosed via hard link (code={code:#07b})"
            );
            assert!(
                !cl_disclosed,
                "SECURITY: ~/Library file contents disclosed via clonefile (code={code:#07b})"
            );
        }
    }
}

/// Test: sandboxed process can read+write helm's config home (~/Library/Preferences/helm)
/// and data home (~/Library/helm), both of which sit under the ~/Library deny.
#[test]
fn sandboxed_helm_config_and_data_homes() {
    if common::already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-e2e-helm"),
        Path::new(&home),
        &[],
        true,
        None,
        &[],
    )
    .unwrap();
    std::fs::create_dir_all("/tmp/ziplock-e2e-helm").ok();

    // Pre-create the helm homes outside the sandbox so the test exercises file
    // ops within them rather than directory creation under ~/Library.
    let config_home = format!("{home}/Library/Preferences/helm");
    let data_home = format!("{home}/Library/helm");
    std::fs::create_dir_all(&config_home).ok();
    std::fs::create_dir_all(&data_home).ok();

    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        nix::unistd::ForkResult::Child => {
            common::apply_sandbox(&profile).unwrap_or_else(|e| {
                eprintln!("sandbox_init failed: {e}");
                std::process::exit(99);
            });

            // Config home: helm rewrites repositories.yaml / repositories.lock here.
            let cfg_file = format!("{config_home}/.ziplock-e2e");
            std::fs::write(&cfg_file, b"repo: test\n")
                .expect("should be able to write helm config home");
            assert_eq!(
                std::fs::read(&cfg_file).expect("should be able to read helm config home"),
                b"repo: test\n"
            );
            std::fs::remove_file(&cfg_file).ok();

            // Data home: helm stores plugins / repo cache here.
            let data_file = format!("{data_home}/.ziplock-e2e");
            std::fs::write(&data_file, b"plugin\n")
                .expect("should be able to write helm data home");
            assert!(
                std::fs::read_dir(&data_home).is_ok(),
                "should be able to read helm data home"
            );
            std::fs::remove_file(&data_file).ok();

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
