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
    // SANDBOX_FILTER_PATH=3, SANDBOX_CHECK_NO_REPORT=4; vararg is const char* path
    fn sandbox_check(pid: nix::libc::pid_t, operation: *const c_char, op_type: c_int, ...)
    -> c_int;
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
        false,
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
fn sandbox_allows_reads_to_keychains() {
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
        false,
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
            result.is_ok(),
            "should be able to read ~/Library/Keychains (carve-out for developer tools)"
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
        false,
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
        false,
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
fn sandbox_allows_reads_to_system_sandbox_profiles() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // sandbox-exec (used internally by xcodebuild to sandbox build steps and test
    // runners) looks up named profiles like "system.sb" from
    // /System/Library/Sandbox/Profiles/. Without this carve-out, reads to /System
    // are denied and sandbox-exec fails with "unable to open 'system.sb': not found",
    // causing xcodebuild test runs to fail even though they work outside ziplock.
    let profiles_path = "/System/Library/Sandbox/Profiles";
    if !Path::new(profiles_path).exists() {
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-sbprofiles"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-sbprofiles").ok();

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(profiles_path);
        assert!(
            result.is_ok(),
            "should be able to read /System/Library/Sandbox/Profiles (needed for sandbox-exec/xcodebuild): {:?}",
            result.err()
        );
        let system_sb = format!("{profiles_path}/system.sb");
        if Path::new(&system_sb).exists() {
            let result = std::fs::metadata(&system_sb);
            assert!(
                result.is_ok(),
                "should be able to read system.sb: {:?}",
                result.err()
            );
        }
    });

    assert_eq!(code, 0, "sandbox profiles read test failed in child");
}

#[test]
fn sandbox_allows_xcode_developer_dir() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let dev_dir = format!("{home}/Library/Developer");
    if !Path::new(&dev_dir).exists() {
        return;
    }

    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-xcode"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-xcode").ok();

    let code = run_sandboxed(&profile, move || {
        // Read: Xcode schemes, device support files, CoreSimulator runtimes
        let result = std::fs::read_dir(&dev_dir);
        assert!(
            result.is_ok(),
            "should be able to read ~/Library/Developer: {:?}",
            result.err()
        );

        // Write: DerivedData (xcodebuild build output)
        let derived_data = format!("{dev_dir}/Xcode/DerivedData");
        std::fs::create_dir_all(&derived_data).ok();
        let test_file = format!("{derived_data}/.ziplock-write-test");
        let write_result = std::fs::write(&test_file, b"ok");
        assert!(
            write_result.is_ok(),
            "should be able to write to ~/Library/Developer/Xcode/DerivedData: {:?}",
            write_result.err()
        );
        std::fs::remove_file(&test_file).ok();
    });

    assert_eq!(code, 0, "xcode developer dir test failed in child");
}

#[test]
fn sandbox_allows_reads_to_system_preferences() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // /Library/Preferences is where xcodebuild stores its accepted-license state.
    // If this directory isn't readable, xcodebuild will always prompt for license
    // acceptance even after `sudo xcodebuild -license accept` has been run.
    let pref_path = "/Library/Preferences";
    if !Path::new(pref_path).exists() {
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-sysprefs"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-sysprefs").ok();

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(pref_path);
        assert!(
            result.is_ok(),
            "should be able to read /Library/Preferences (needed for xcodebuild license): {:?}",
            result.err()
        );
        // Specifically verify the Xcode plist is accessible if present
        let xcode_plist = "/Library/Preferences/com.apple.dt.Xcode.plist";
        if Path::new(xcode_plist).exists() {
            let result = std::fs::metadata(xcode_plist);
            assert!(
                result.is_ok(),
                "should be able to read com.apple.dt.Xcode.plist: {:?}",
                result.err()
            );
        }
    });

    assert_eq!(
        code, 0,
        "sandbox system preferences read test failed in child"
    );
}

#[test]
fn sandbox_allows_reads_to_system_assetsv2() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // /System/Library/AssetsV2 contains cryptex volumes (e.g. MetalToolchainCryptex)
    // that xcodebuild probes at startup. Without this carve-out, Metal Toolchain
    // appears "missing" inside the sandbox even after `xcodebuild -downloadComponent
    // MetalToolchain` has run successfully outside it.
    let assets_path = "/System/Library/AssetsV2";
    if !Path::new(assets_path).exists() {
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-assetsv2"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-assetsv2").ok();

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(assets_path);
        assert!(
            result.is_ok(),
            "should be able to read /System/Library/AssetsV2 (Metal Toolchain/cryptex): {:?}",
            result.err()
        );
    });

    assert_eq!(code, 0, "sandbox AssetsV2 read test failed in child");
}

#[test]
fn sandbox_allows_reads_to_system_keychains() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // /Library/Keychains is read by SecItemCopyMatching (the macOS Keychain API)
    // when fetching credentials. Without this carve-out, `xcodebuild` fails with
    // "failedToStart" error 74 — logged as "CSSM Exception: 100001 UNIX[Operation
    // not permitted]" in the system log. Developer tools like `gh` also use this path.
    let keychain_path = "/Library/Keychains";
    if !Path::new(keychain_path).exists() {
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-syskeychains"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-syskeychains").ok();

    let code = run_sandboxed(&profile, move || {
        let result = std::fs::read_dir(keychain_path);
        assert!(
            result.is_ok(),
            "should be able to read /Library/Keychains (required for SecItemCopyMatching): {:?}",
            result.err()
        );
    });

    assert_eq!(
        code, 0,
        "sandbox system keychains read test failed in child"
    );
}

#[test]
fn sandbox_allows_swift_package_manager() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // ~/Library/org.swift.swiftpm is used by Swift Package Manager for package cache,
    // resolved dependencies, and security scope bookmarks. Without read+write access,
    // SPM fails to resolve packages and xcodebuild cannot build Swift projects.
    let home = std::env::var("HOME").unwrap();
    let spm_dir = format!("{home}/Library/org.swift.swiftpm");

    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-swiftpm"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-swiftpm").ok();
    std::fs::create_dir_all(&spm_dir).ok();

    let code = run_sandboxed(&profile, move || {
        // Read access
        let result = std::fs::read_dir(&spm_dir);
        assert!(
            result.is_ok(),
            "should be able to read ~/Library/org.swift.swiftpm: {:?}",
            result.err()
        );

        // Write access (SPM writes security scope bookmarks and package cache here)
        let test_file = format!("{spm_dir}/.ziplock-write-test");
        let write_result = std::fs::write(&test_file, b"ok");
        assert!(
            write_result.is_ok(),
            "should be able to write to ~/Library/org.swift.swiftpm: {:?}",
            write_result.err()
        );
        std::fs::remove_file(&test_file).ok();
    });

    assert_eq!(
        code, 0,
        "sandbox Swift Package Manager test failed in child"
    );
}

// Spawning grandchild processes (cat, sh) inside a doubly-sandboxed process
// (ziplock's own sandbox + the test's sandbox) causes a deadlock because
// already_sandboxed() falsely returns false inside ziplock. Run manually:
//   cargo test -- --ignored sandbox_allows_cat_and_standard_unix_tools
#[test]
#[ignore]
fn sandbox_allows_cat_and_standard_unix_tools() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-cat"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    std::fs::create_dir_all("/tmp/ziplock-test-cat").ok();

    let code = run_sandboxed(&profile, || {
        // Write a file to read back
        let test_file = "/tmp/ziplock-test-cat/hello.txt";
        std::fs::write(test_file, b"hello from cat test").unwrap();

        // Direct exec of /bin/cat (no PATH lookup).
        let output = std::process::Command::new("/bin/cat")
            .arg(test_file)
            .output()
            .expect("/bin/cat failed to spawn");
        assert!(
            output.status.success(),
            "/bin/cat exited with status {}: stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "hello from cat test"
        );

        // Shell-based PATH lookup for grep and head — regression for the macOS 11+
        // firmlink bug where /usr/bin/* was blocked inside the sandbox.
        // This mimics how Claude Code invokes tools: via a shell, not direct exec.
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("grep 'hello' /tmp/ziplock-test-cat/hello.txt | head -1")
            .output()
            .expect("sh -c grep|head failed to spawn");
        assert!(
            output.status.success(),
            "grep/head via shell PATH lookup failed (status {}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("hello"),
            "grep output missing expected content: {}",
            String::from_utf8_lossy(&output.stdout)
        );

        // For-loop with pipeline inside $() — mirrors how Claude Code bash tool
        // runs multi-line scripts. Earlier bug: grep/head/tr not found only inside
        // for loops, not in single-command invocations.
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(concat!(
                "out=''; ",
                "for x in a b c; do ",
                "  result=$(echo \"hello $x\" | grep 'hello' | head -1 | tr 'a-z' 'A-Z'); ",
                "  out=\"$out $result\"; ",
                "done; ",
                "echo \"$out\""
            ))
            .output()
            .expect("sh for-loop test failed to spawn");
        assert!(
            output.status.success(),
            "for-loop grep/head/tr failed (status {}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let result = String::from_utf8_lossy(&output.stdout);
        assert!(
            result.contains("HELLO"),
            "for-loop output missing expected content: {result}"
        );

        std::fs::remove_file(test_file).ok();
    });

    assert_eq!(code, 0, "cat execution test failed in child");
}

#[test]
fn sandbox_extra_allow_path() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    let home = std::env::var("HOME").unwrap();

    // Dirs must exist before generate_profile so canonicalize() succeeds.
    std::fs::create_dir_all("/tmp/ziplock-test-extra").ok();
    std::fs::create_dir_all("/tmp/ziplock-extra-allowed").ok();

    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp/ziplock-test-extra"),
        Path::new(&home),
        &[PathBuf::from("/tmp/ziplock-extra-allowed")],
        true,
        false,
        None,
    )
    .unwrap();

    let code = run_sandboxed(&profile, || {
        let test_file = "/tmp/ziplock-extra-allowed/extra-write-test.txt";
        std::fs::write(test_file, b"extra path allowed")
            .expect("write to --allow-path should succeed");
        std::fs::remove_file(test_file).ok();
    });

    assert_eq!(code, 0, "sandbox extra allow-path test failed in child");
}

// Spawning grandchild processes inside a doubly-sandboxed process (ziplock's own
// sandbox + the test's sandbox) causes a deadlock because already_sandboxed()
// falsely returns false inside ziplock. Run these manually with --ignored.

// Spawning grandchild processes (codesign) inside a doubly-sandboxed process
// (ziplock's own sandbox + the test's sandbox) causes a deadlock because
// already_sandboxed() falsely returns false inside ziplock. Run manually:
//   cargo test -- --ignored sandbox_allows_codesign_ad_hoc
#[test]
#[ignore]
fn sandbox_allows_codesign_ad_hoc() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    // codesign --sign - (ad-hoc signing) calls sandbox_check() against
    // ~/Library/Security and /Library/Security (trust settings) before signing.
    // Without read carve-outs for those paths, sandbox_check() returns EPERM
    // and codesign exits "Operation not permitted" without logging any violation.
    let home = std::env::var("HOME").unwrap();
    let test_dir = "/tmp/ziplock-test-codesign";
    std::fs::create_dir_all(test_dir).ok();

    // Copy a real Mach-O binary into the test dir so we have something to sign.
    let target_binary = format!("{test_dir}/test-binary");
    std::fs::copy("/bin/ls", &target_binary).expect("failed to copy /bin/ls for codesign test");

    let profile = ziplock::sandbox::generate_profile(
        Path::new(test_dir),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    let code = run_sandboxed(&profile, move || {
        let output = std::process::Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--generate-entitlement-der",
                &target_binary,
            ])
            .output()
            .expect("failed to spawn codesign");
        assert!(
            output.status.success(),
            "codesign --sign - failed (status {}): stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    });

    std::fs::remove_file(format!("{test_dir}/test-binary")).ok();
    assert_eq!(code, 0, "codesign ad-hoc signing test failed in child");
}

// Full xcodebuild framework build inside the sandbox. Uses xcodegen to generate
// the .xcodeproj from a project.yml so we don't have to hand-craft pbxproj.
// Exercises: xcodegen, Swift compilation, codesign, builtin-copy,
// builtin-RegisterExecutionPolicyException, DerivedData writes.
// Requires xcodegen on PATH (`brew install xcodegen`).
// Run manually: cargo test -- --ignored sandbox_allows_xcodebuild_framework_build
#[test]
#[ignore]
fn sandbox_allows_xcodebuild_framework_build() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    if which::which("xcodegen").is_err() {
        eprintln!("skipping: xcodegen not found on PATH (brew install xcodegen)");
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let test_dir = "/tmp/ziplock-test-xcodebuild";
    std::fs::create_dir_all(test_dir).ok();

    let profile = ziplock::sandbox::generate_profile(
        Path::new(test_dir),
        Path::new(&home),
        &[],
        true, // allow_network: skip DNS proxy so xcodebuild can reach Apple CDN if needed
        false,
        None,
    )
    .unwrap();

    let code = run_sandboxed(&profile, move || {
        // Write project.yml
        std::fs::write(
            format!("{test_dir}/project.yml"),
            "name: ZiplockTestApp\n\
             packages:\n\
             \x20 SwiftTerm:\n\
             \x20\x20\x20 url: https://github.com/migueldeicaza/SwiftTerm.git\n\
             \x20\x20\x20 branch: main\n\
             targets:\n\
             \x20 ZiplockTestApp:\n\
             \x20\x20\x20 type: application\n\
             \x20\x20\x20 platform: macOS\n\
             \x20\x20\x20 deploymentTarget: \"14.0\"\n\
             \x20\x20\x20 sources:\n\
             \x20\x20\x20\x20\x20 - Sources\n\
             \x20\x20\x20 dependencies:\n\
             \x20\x20\x20\x20\x20 - package: SwiftTerm\n\
             \x20\x20\x20 settings:\n\
             \x20\x20\x20\x20\x20 GENERATE_INFOPLIST_FILE: YES\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_IDENTITY: \"-\"\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_STYLE: Manual\n\
             \x20\x20\x20\x20\x20 ENABLE_HARDENED_RUNTIME: NO\n",
        )
        .expect("failed to write project.yml");

        // Write a minimal Swift app that imports SwiftTerm to force linking
        std::fs::create_dir_all(format!("{test_dir}/Sources")).ok();
        std::fs::write(
            format!("{test_dir}/Sources/main.swift"),
            "import Foundation\nimport SwiftTerm\n",
        )
        .expect("failed to write Swift source");

        // Generate the .xcodeproj
        let out = std::process::Command::new("xcodegen")
            .args([
                "generate",
                "--spec",
                &format!("{test_dir}/project.yml"),
                "--project",
                test_dir,
            ])
            .current_dir(test_dir)
            .output()
            .expect("failed to spawn xcodegen");
        assert!(
            out.status.success(),
            "xcodegen failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        // Build — redirect DerivedData into the test dir so cleanup is easy.
        // sandbox-exec (used by SPM for swiftc manifest compilation and by xcodebuild
        // for build steps) calls sandbox_apply() which is blocked inside ziplock's SBPL
        // profile. No valid SBPL op name allows it selectively, so disable SPM's own
        // sandboxing via env vars and -IDEPackageSupportDisableManifestSandbox=YES.
        let derived_data = format!("{test_dir}/DerivedData");
        let out = std::process::Command::new("xcodebuild")
            .env("SWIFTPM_SANDBOX", "0")
            .env("XBS_DISABLE_SANDBOXED_BUILDS", "1")
            .args([
                "build",
                "-project",
                &format!("{test_dir}/ZiplockTestApp.xcodeproj"),
                "-scheme",
                "ZiplockTestApp",
                "-configuration",
                "Debug",
                "-derivedDataPath",
                &derived_data,
                "-IDEPackageSupportDisableManifestSandbox=YES",
            ])
            .current_dir(test_dir)
            .output()
            .expect("failed to spawn xcodebuild");
        assert!(
            out.status.success(),
            "xcodebuild failed ({}): stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    });

    assert_eq!(code, 0, "xcodebuild app build test failed in child");
    std::fs::remove_dir_all(test_dir).ok();
}

// Diagnostic: call sandbox_check() directly for every file operation on both
// /tmp (known-good) and ~/Library/Developer (failing) to identify the denied op.
// Verify that codesign can sign files in ~/Library/* subdirectories inside the sandbox.
// codesign (via AMFI) calls sandbox_check() on each ancestor directory before signing.
// ~/Library itself needs both file-read* and file-write* ALLOW (via literal carve-out)
// even though its contents are protected. Run manually:
//   cargo test -- --test-threads=1 --ignored sandbox_allows_codesign_in_library
#[test]
#[ignore]
fn sandbox_allows_codesign_in_library() {
    if already_sandboxed() {
        return;
    }
    let home = std::env::var("HOME").unwrap();
    let profile = ziplock::sandbox::generate_profile(
        Path::new("/tmp"),
        Path::new(&home),
        &[],
        true,
        false,
        None,
    )
    .unwrap();

    let code = run_sandboxed(&profile, move || {
        let home = std::env::var("HOME").unwrap();

        // Verify ~/Library itself is ALLOW inside the sandbox
        let check_r = {
            let op = CString::new("file-read-data").unwrap();
            let path = CString::new(format!("{home}/Library")).unwrap();
            unsafe { sandbox_check(nix::libc::getpid(), op.as_ptr(), 1, path.as_ptr()) }
        };
        let check_w = {
            let op = CString::new("file-write-data").unwrap();
            let path = CString::new(format!("{home}/Library")).unwrap();
            unsafe { sandbox_check(nix::libc::getpid(), op.as_ptr(), 1, path.as_ptr()) }
        };
        assert_eq!(
            check_r, 0,
            "file-read-data on ~/Library must be ALLOW (codesign ancestor check)"
        );
        assert_eq!(
            check_w, 0,
            "file-write-data on ~/Library must be ALLOW (codesign ancestor check)"
        );

        // codesign must work on files under ~/Library/Developer
        let dev_file =
            format!("{home}/Library/Developer/Xcode/DerivedData/ziplock-cs-library-test");
        std::fs::copy("/bin/ls", &dev_file).expect("copy binary to DerivedData");
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none", &dev_file])
            .output()
            .expect("spawn codesign");
        std::fs::remove_file(&dev_file).ok();
        assert!(
            out.status.success(),
            "codesign in ~/Library/Developer failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );

        // Also verify ~/Library/Caches (another carve-out subdirectory)
        let caches_file = format!("{home}/Library/Caches/ziplock-cs-library-test");
        std::fs::copy("/bin/ls", &caches_file).expect("copy binary to Caches");
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none", &caches_file])
            .output()
            .expect("spawn codesign caches");
        std::fs::remove_file(&caches_file).ok();
        assert!(
            out.status.success(),
            "codesign in ~/Library/Caches failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    });
    assert_eq!(
        code, 0,
        "sandbox_allows_codesign_in_library failed in sandbox"
    );
}

// End-to-end xcodebuild test using the default DerivedData location
// (~/Library/Developer/Xcode/DerivedData). This is the key test for the
// ~/Library literal carve-out: xcodebuild writes to DerivedData and codesign
// signs the resulting binary there — both require the ancestor-directory
// sandbox_check() on ~/Library to pass.
//
// Uses xcodegen to generate a minimal no-dependency Swift app. No network needed.
// Run manually: cargo test -- --test-threads=1 --ignored sandbox_allows_xcodebuild_deriveddata
#[test]
#[ignore]
fn sandbox_allows_xcodebuild_deriveddata() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    if which::which("xcodegen").is_err() {
        eprintln!("skipping: xcodegen not found on PATH (brew install xcodegen)");
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let test_dir = "/tmp/ziplock-test-deriveddata";
    let derived_data =
        format!("{home}/Library/Developer/Xcode/DerivedData/ziplock-test-deriveddata");
    std::fs::create_dir_all(test_dir).ok();

    let profile = ziplock::sandbox::generate_profile(
        Path::new(test_dir),
        Path::new(&home),
        &[],
        true, // allow_network: skip DNS proxy; test is offline but xcodebuild needs Apple CDN for toolchain metadata
        false,
        None,
    )
    .unwrap();

    let derived_data_inner = derived_data.clone();
    let code = run_sandboxed(&profile, move || {
        let derived_data = &derived_data_inner;
        // Minimal Swift app — no SPM dependencies, no network required
        std::fs::write(
            format!("{test_dir}/project.yml"),
            "name: ZiplockMinBuild\n\
             targets:\n\
             \x20 ZiplockMinBuild:\n\
             \x20\x20\x20 type: application\n\
             \x20\x20\x20 platform: macOS\n\
             \x20\x20\x20 deploymentTarget: \"14.0\"\n\
             \x20\x20\x20 sources:\n\
             \x20\x20\x20\x20\x20 - Sources\n\
             \x20\x20\x20 settings:\n\
             \x20\x20\x20\x20\x20 GENERATE_INFOPLIST_FILE: YES\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_IDENTITY: \"-\"\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_STYLE: Manual\n\
             \x20\x20\x20\x20\x20 ENABLE_HARDENED_RUNTIME: NO\n",
        )
        .expect("write project.yml");

        std::fs::create_dir_all(format!("{test_dir}/Sources")).ok();
        std::fs::write(
            format!("{test_dir}/Sources/main.swift"),
            "print(\"ziplock sandbox test\")\n",
        )
        .expect("write main.swift");

        let out = std::process::Command::new("xcodegen")
            .args([
                "generate",
                "--spec",
                &format!("{test_dir}/project.yml"),
                "--project",
                test_dir,
            ])
            .current_dir(test_dir)
            .output()
            .expect("spawn xcodegen");
        assert!(
            out.status.success(),
            "xcodegen failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Build with DerivedData in ~/Library/Developer — exercises the ~/Library
        // literal carve-out: codesign checks file-read/write-data on ~/Library itself.
        let out = std::process::Command::new("xcodebuild")
            .env("SWIFTPM_SANDBOX", "0")
            .env("XBS_DISABLE_SANDBOXED_BUILDS", "1")
            .args([
                "build",
                "-project",
                &format!("{test_dir}/ZiplockMinBuild.xcodeproj"),
                "-scheme",
                "ZiplockMinBuild",
                "-configuration",
                "Debug",
                "-derivedDataPath",
                derived_data,
                "-IDEPackageSupportDisableManifestSandbox=YES",
            ])
            .current_dir(test_dir)
            .output()
            .expect("spawn xcodebuild");
        assert!(
            out.status.success(),
            "xcodebuild failed ({}):\nstdout={}\nstderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    });

    std::fs::remove_dir_all(test_dir).ok();
    std::fs::remove_dir_all(&derived_data).ok();
    assert_eq!(code, 0, "sandbox_allows_xcodebuild_deriveddata failed");
}

// Run `xcodebuild test` for a minimal macOS XCTest bundle inside the sandbox.
// Exercises testmanagerd and testmanagerd.control (the XCTest runner daemon and
// its control endpoint), plus the full build + sign + run path for unit tests.
// Requires xcodegen on PATH (`brew install xcodegen`).
// Run manually: cargo test -- --test-threads=1 --ignored sandbox_allows_xcodebuild_test
#[test]
#[ignore]
fn sandbox_allows_xcodebuild_test() {
    if already_sandboxed() {
        eprintln!("skipping: already running inside a sandbox");
        return;
    }
    if which::which("xcodegen").is_err() {
        eprintln!("skipping: xcodegen not found on PATH (brew install xcodegen)");
        return;
    }

    let home = std::env::var("HOME").unwrap();
    let test_dir = "/tmp/ziplock-test-xctest";
    std::fs::create_dir_all(test_dir).ok();

    let profile = ziplock::sandbox::generate_profile(
        Path::new(test_dir),
        Path::new(&home),
        &[],
        true, // allow_network: xcodebuild may reach Apple CDN for toolchain metadata
        false,
        None,
    )
    .unwrap();

    let code = run_sandboxed(&profile, move || {
        // A static library to test against
        std::fs::create_dir_all(format!("{test_dir}/Sources/Lib")).ok();
        std::fs::write(
            format!("{test_dir}/Sources/Lib/Lib.swift"),
            "public func answer() -> Int { 42 }\n",
        )
        .expect("write Lib.swift");

        // XCTest bundle with one passing test
        std::fs::create_dir_all(format!("{test_dir}/Sources/Tests")).ok();
        std::fs::write(
            format!("{test_dir}/Sources/Tests/LibTests.swift"),
            "import XCTest\n\
             @testable import ZiplockTestLib\n\
             final class LibTests: XCTestCase {\n\
             \x20   func testAnswer() { XCTAssertEqual(answer(), 42) }\n\
             }\n",
        )
        .expect("write LibTests.swift");

        // project.yml: static lib + macOS unit test bundle
        std::fs::write(
            format!("{test_dir}/project.yml"),
            "name: ZiplockTestRunner\n\
             targets:\n\
             \x20 ZiplockTestLib:\n\
             \x20\x20\x20 type: library.static\n\
             \x20\x20\x20 platform: macOS\n\
             \x20\x20\x20 deploymentTarget: \"14.0\"\n\
             \x20\x20\x20 sources:\n\
             \x20\x20\x20\x20\x20 - Sources/Lib\n\
             \x20\x20\x20 settings:\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_IDENTITY: \"-\"\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_STYLE: Manual\n\
             \x20\x20\x20\x20\x20 ENABLE_HARDENED_RUNTIME: NO\n\
             \x20 ZiplockTestRunnerTests:\n\
             \x20\x20\x20 type: bundle.unit-test\n\
             \x20\x20\x20 platform: macOS\n\
             \x20\x20\x20 deploymentTarget: \"14.0\"\n\
             \x20\x20\x20 sources:\n\
             \x20\x20\x20\x20\x20 - Sources/Tests\n\
             \x20\x20\x20 dependencies:\n\
             \x20\x20\x20\x20\x20 - target: ZiplockTestLib\n\
             \x20\x20\x20 settings:\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_IDENTITY: \"-\"\n\
             \x20\x20\x20\x20\x20 CODE_SIGN_STYLE: Manual\n\
             \x20\x20\x20\x20\x20 ENABLE_HARDENED_RUNTIME: NO\n\
             \x20\x20\x20\x20\x20 GENERATE_INFOPLIST_FILE: YES\n",
        )
        .expect("write project.yml");

        // Generate .xcodeproj
        let out = std::process::Command::new("xcodegen")
            .args([
                "generate",
                "--spec",
                &format!("{test_dir}/project.yml"),
                "--project",
                test_dir,
            ])
            .current_dir(test_dir)
            .output()
            .expect("spawn xcodegen");
        assert!(
            out.status.success(),
            "xcodegen failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        // Run tests — macOS destination, DerivedData in test dir for easy cleanup
        let derived_data = format!("{test_dir}/DerivedData");
        let out = std::process::Command::new("xcodebuild")
            .env("SWIFTPM_SANDBOX", "0")
            .env("XBS_DISABLE_SANDBOXED_BUILDS", "1")
            .args([
                "test",
                "-project",
                &format!("{test_dir}/ZiplockTestRunner.xcodeproj"),
                "-scheme",
                "ZiplockTestRunnerTests",
                "-destination",
                "platform=macOS,arch=arm64",
                "-derivedDataPath",
                &derived_data,
                "-IDEPackageSupportDisableManifestSandbox=YES",
            ])
            .current_dir(test_dir)
            .output()
            .expect("spawn xcodebuild test");
        assert!(
            out.status.success(),
            "xcodebuild test failed ({}):\nstdout={}\nstderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    });

    std::fs::remove_dir_all(test_dir).ok();
    assert_eq!(code, 0, "sandbox_allows_xcodebuild_test failed");
}
