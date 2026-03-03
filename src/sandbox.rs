use std::ffi::{CString, c_char, c_int};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use tracing::debug;

use crate::proxy::ProxyPorts;

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Sanitize a path for safe interpolation into an SBPL profile string.
/// Rejects paths containing characters that could break out of SBPL string literals.
fn sanitize_sbpl_path(path: &Path) -> Result<String> {
    let s = path.to_string_lossy().into_owned();
    // SBPL uses "..." string literals. A `"` in the path would terminate the literal
    // and allow injection of arbitrary sandbox rules. Reject any path containing
    // characters that are meaningful in SBPL syntax.
    if s.contains('"') || s.contains('\\') {
        anyhow::bail!(
            "path contains characters unsafe for sandbox profile: {}",
            path.display()
        );
    }
    Ok(s)
}

/// Generate the SBPL (Seatbelt Profile Language) sandbox profile.
pub fn generate_profile(
    cwd: &Path,
    home: &Path,
    allow_paths: &[PathBuf],
    allow_network: bool,
) -> Result<String> {
    let cwd_str = sanitize_sbpl_path(cwd)?;
    let home_str = sanitize_sbpl_path(home)?;

    let mut extra_write_rules = String::new();
    for path in allow_paths {
        let safe = sanitize_sbpl_path(path)?;
        extra_write_rules.push_str(&format!("    (subpath \"{safe}\")\n"));
    }

    let network_rules = if allow_network {
        "  (allow network*)".to_string()
    } else {
        r#"  ;; Only allow localhost connections (forces traffic through proxy)
  (allow network-outbound
    (remote ip "localhost:*"))
  (allow network-inbound
    (local ip "localhost:*"))
  (allow network-bind
    (local ip "localhost:*"))
  ;; Allow unix domain sockets (needed for various IPC)
  (allow network-outbound (remote unix-socket))
  (allow network-inbound (local unix-socket))
  (allow network-bind (local unix-socket))"#
            .to_string()
    };

    Ok(format!(
        r#"(version 1)
(deny default)

;; ── Process ──────────────────────────────────────────────────────────────
(allow process-exec*)
(allow process-fork)
(allow signal (target same-sandbox))

;; ── File reads: allow most, deny sensitive system trees ──────────────────
(allow file-read*)

;; Deny sensitive system locations
(deny file-read*
    (subpath "{home_str}/Library")
    (subpath "/Library")
    (subpath "/System"))

;; Carve-outs: frameworks and developer tools needed for process execution
(allow file-read*
    (subpath "/System/Library/Frameworks")
    (subpath "/System/Library/PrivateFrameworks")
    (subpath "/System/Library/dyld")
    (subpath "/System/Library/CoreServices")
    (subpath "/System/Library/Perl")
    (subpath "/System/Library/OpenSSL")
    (subpath "/Library/Frameworks")
    (subpath "/Library/Developer")
    (subpath "/Library/Apple")
    (subpath "{home_str}/Library/Preferences"))

;; ── File writes: only allowed locations ──────────────────────────────────
(allow file-write*
    (subpath "{cwd_str}")
    (subpath "/tmp")
    (subpath "/private/tmp")
    (subpath "{home_str}/.claude")
    (subpath "{home_str}/.local/share/claude")
{extra_write_rules})

;; ── Network ──────────────────────────────────────────────────────────────
{network_rules}

;; ── Mach IPC: whitelist services needed for TLS, fonts, logging ──────────
(allow mach-lookup
    (global-name "com.apple.trustd.agent")
    (global-name "com.apple.trustd")
    (global-name "com.apple.ocspd")
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.system.opendirectoryd.libinfo")
    (global-name "com.apple.system.logger")
    (global-name "com.apple.system.notification_center")
    (global-name "com.apple.CoreServices.coreservicesd")
    (global-name "com.apple.DiskArbitration.diskarbitrationd")
    (global-name "com.apple.lsd.mapdb")
    (global-name "com.apple.fonts")
    (global-name "com.apple.cfprefsd.daemon")
    (global-name "com.apple.cfprefsd.agent")
    (global-name "com.apple.runningboard"))

;; ── PTY (needed for interactive terminal) ────────────────────────────────
(allow pseudo-tty)
(allow file-read* file-write*
    (literal "/dev/ptmx")
    (regex #"/dev/ttys[0-9]+"))

;; ── Misc: sysctl, IOKit, POSIX IPC ──────────────────────────────────────
(allow sysctl-read)
(allow iokit-open)
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-shm-write-create)

;; ── Pipe and FD operations ───────────────────────────────────────────────
(allow file-read* file-write*
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/dtracehelper"))
"#,
    ))
}

/// Spawn the claude process with sandbox applied via pre_exec.
pub fn spawn_claude(
    claude_path: &Path,
    cwd: &Path,
    home: &Path,
    claude_args: &[String],
    allow_paths: &[PathBuf],
    allow_network: bool,
    ports: &ProxyPorts,
) -> Result<std::process::Child> {
    let profile = generate_profile(cwd, home, allow_paths, allow_network)?;
    debug!("SBPL profile:\n{profile}");

    let mut cmd = Command::new(claude_path);
    cmd.arg("--dangerously-skip-permissions");
    cmd.args(claude_args);
    cmd.current_dir(cwd);

    // Set proxy env vars
    if !allow_network {
        let socks_url = format!("socks5h://127.0.0.1:{}", ports.socks5);
        let http_url = format!("http://127.0.0.1:{}", ports.http);

        cmd.env("ALL_PROXY", &socks_url);
        cmd.env("all_proxy", &socks_url);
        cmd.env("HTTP_PROXY", &http_url);
        cmd.env("http_proxy", &http_url);
        cmd.env("HTTPS_PROXY", &http_url);
        cmd.env("https_proxy", &http_url);
        cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
        cmd.env("no_proxy", "localhost,127.0.0.1,::1");
        cmd.env(
            "GIT_SSH_COMMAND",
            format!(
                "ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:{} %h %p'",
                ports.socks5
            ),
        );
    }

    // Ensure /tmp/claude exists and set TMPDIR
    let tmp_claude = PathBuf::from("/tmp/claude");
    if !tmp_claude.exists() {
        std::fs::create_dir_all(&tmp_claude).context("failed to create /tmp/claude")?;
    }
    cmd.env("TMPDIR", "/tmp/claude");

    // Apply sandbox in pre_exec (after fork, before exec)
    let profile_for_closure = profile.clone();
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

    let child = cmd.spawn().context("failed to spawn claude")?;
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn profile_contains_cwd_and_home() {
        let profile = generate_profile(
            Path::new("/Users/test/project"),
            Path::new("/Users/test"),
            &[],
            false,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/Users/test/project")"#));
        assert!(profile.contains(r#"(subpath "/Users/test/.claude")"#));
        assert!(profile.contains(r#"(subpath "/Users/test/.local/share/claude")"#));
    }

    #[test]
    fn profile_denies_sensitive_paths() {
        let profile = generate_profile(
            Path::new("/Users/test/project"),
            Path::new("/Users/test"),
            &[],
            false,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/Users/test/Library")"#));
        assert!(profile.contains(r#"(subpath "/Library")"#));
        assert!(profile.contains(r#"(subpath "/System")"#));
    }

    #[test]
    fn profile_has_framework_carveouts() {
        let profile =
            generate_profile(Path::new("/tmp/proj"), Path::new("/Users/test"), &[], false).unwrap();
        assert!(profile.contains(r#"(subpath "/System/Library/Frameworks")"#));
        assert!(profile.contains(r#"(subpath "/Library/Developer")"#));
        assert!(profile.contains(r#"(subpath "/Library/Apple")"#));
    }

    #[test]
    fn profile_localhost_only_network_by_default() {
        let profile =
            generate_profile(Path::new("/tmp/proj"), Path::new("/Users/test"), &[], false).unwrap();
        assert!(profile.contains(r#"(remote ip "localhost:*")"#));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn profile_allow_network_flag() {
        let profile =
            generate_profile(Path::new("/tmp/proj"), Path::new("/Users/test"), &[], true).unwrap();
        assert!(profile.contains("(allow network*)"));
        assert!(!profile.contains(r#"(remote ip "localhost:*")"#));
    }

    #[test]
    fn profile_extra_allow_paths() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[PathBuf::from("/extra/path"), PathBuf::from("/another/path")],
            false,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/extra/path")"#));
        assert!(profile.contains(r#"(subpath "/another/path")"#));
    }

    #[test]
    fn profile_rejects_path_with_quotes() {
        let result = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[PathBuf::from(
                r#"/tmp/evil")(allow network*)(subpath "/tmp"#,
            )],
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn profile_rejects_cwd_with_quotes() {
        let result = generate_profile(
            Path::new(r#"/tmp/evil")(allow network*"#),
            Path::new("/Users/test"),
            &[],
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn profile_no_security_server_mach_lookup() {
        let profile =
            generate_profile(Path::new("/tmp/proj"), Path::new("/Users/test"), &[], false).unwrap();
        assert!(
            !profile.contains("com.apple.SecurityServer"),
            "SecurityServer Mach IPC should not be whitelisted (keychain bypass)"
        );
    }
}
