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
    ssh_agent_dir: Option<&Path>,
) -> Result<String> {
    let cwd_str = sanitize_sbpl_path(cwd)?;
    let home_str = sanitize_sbpl_path(home)?;

    let mut extra_write_rules = String::new();
    for path in allow_paths {
        let safe = sanitize_sbpl_path(path)?;
        extra_write_rules.push_str(&format!("    (subpath \"{safe}\")\n"));
    }

    let ssh_agent_rule = if let Some(dir) = ssh_agent_dir {
        let safe = sanitize_sbpl_path(dir)?;
        format!("    (subpath \"{safe}\")\n")
    } else {
        String::new()
    };

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
(allow process-info*)
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
    (subpath "{home_str}/Library/Preferences")
    (subpath "{home_str}/Library/Caches")
{ssh_agent_rule})

;; ── File writes ────────────────────────────────────────────────────────
;; Allow writes to home dir broadly (excluding sensitive ~/Library subtree)
;; then restrict further to only allowed paths
(allow file-write*
    (subpath "{cwd_str}")
    (subpath "{home_str}")
    (subpath "/tmp")
    (subpath "/private/tmp")
    (subpath "/private/var")
    (subpath "/var")
{extra_write_rules})
;; Block writes to sensitive home subdirectory
(deny file-write*
    (subpath "{home_str}/Library"))
;; Re-allow caches (build tools: Go, npm, pip, Homebrew, etc.)
(allow file-write*
    (subpath "{home_str}/Library/Caches"))

;; ── Network ──────────────────────────────────────────────────────────────
{network_rules}

;; ── Mach / XPC IPC ──────────────────────────────────────────────────────
(allow mach-lookup)
(allow mach-register)
(allow mach-priv-host-port)
(allow mach-priv-task-port)
(allow mach-task-name)
(allow mach-per-user-lookup)

;; ── PTY (needed for interactive terminal) ────────────────────────────────
(allow pseudo-tty)
(allow file-read* file-write*
    (literal "/dev/ptmx")
    (literal "/dev/tty")
    (regex #"/dev/ttys[0-9]+"))
(allow file-ioctl)

;; ── Misc ─────────────────────────────────────────────────────────────────
(allow sysctl*)
(allow iokit*)
(allow ipc*)
(allow user-preference*)
(allow system-socket)
(allow lsopen)
(allow darwin-notification-post)

;; ── Device and FD operations ─────────────────────────────────────────────
(allow file-read* file-write*
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/dtracehelper"))
"#,
    ))
}

/// Scan ~/Library/Group Containers/ for a 1Password SSH agent socket.
/// Returns the directory containing agent.sock (to pass as ssh_agent_dir to generate_profile).
fn find_op_agent_socket(home: &Path) -> Option<PathBuf> {
    let group_containers = home.join("Library/Group Containers");
    let entries = std::fs::read_dir(&group_containers).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_lowercase();
        if name_str.contains("1password") || name_str.contains("agilebits") {
            let agent_sock = entry.path().join("t/agent.sock");
            if agent_sock.exists() {
                return agent_sock.parent().map(|p| p.to_path_buf());
            }
        }
    }
    None
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
    // Detect 1Password SSH agent socket for git operations
    let ssh_agent_dir = find_op_agent_socket(home);
    let profile = generate_profile(
        cwd,
        home,
        allow_paths,
        allow_network,
        ssh_agent_dir.as_deref(),
    )?;
    debug!("SBPL profile:\n{profile}");

    let mut cmd = Command::new(claude_path);
    cmd.arg("--dangerously-skip-permissions");
    cmd.args(claude_args);
    cmd.current_dir(cwd);

    // Claude Code refuses to launch if CLAUDECODE is set (nested-session guard).
    // Strip it so ziplock can be run from a Claude Code terminal during development.
    cmd.env_remove("CLAUDECODE");

    // Set SSH_AUTH_SOCK to 1Password agent if found
    if let Some(ref dir) = ssh_agent_dir {
        cmd.env("SSH_AUTH_SOCK", dir.join("agent.sock"));
        debug!("SSH_AUTH_SOCK -> {}", dir.join("agent.sock").display());
    }

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
            None,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/Users/test/project")"#));
        // Home dir is allowed broadly (LSP plugins write throughout $HOME)
        assert!(profile.contains(r#"(subpath "/Users/test")"#));
    }

    #[test]
    fn profile_denies_sensitive_paths() {
        let profile = generate_profile(
            Path::new("/Users/test/project"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/Users/test/Library")"#));
        assert!(profile.contains(r#"(subpath "/Library")"#));
        assert!(profile.contains(r#"(subpath "/System")"#));
    }

    #[test]
    fn profile_has_framework_carveouts() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(profile.contains(r#"(subpath "/System/Library/Frameworks")"#));
        assert!(profile.contains(r#"(subpath "/Library/Developer")"#));
        assert!(profile.contains(r#"(subpath "/Library/Apple")"#));
    }

    #[test]
    fn profile_allows_library_caches() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        // ~/Library/Caches must be readable (Go module cache, npm, pip, etc.)
        assert!(profile.contains(r#"(subpath "/Users/test/Library/Caches")"#));
        // The allow for Caches must appear after the deny for ~/Library (last match wins in SBPL)
        let deny_pos = profile.find(r#"(deny file-write*"#).unwrap();
        let caches_allow_pos = profile
            .rfind(r#"(subpath "/Users/test/Library/Caches")"#)
            .unwrap();
        assert!(
            caches_allow_pos > deny_pos,
            "Caches write allow must come after ~/Library write deny"
        );
    }

    #[test]
    fn profile_localhost_only_network_by_default() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(profile.contains(r#"(remote ip "localhost:*")"#));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn profile_allow_network_flag() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            true,
            None,
        )
        .unwrap();
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
            None,
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
            None,
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
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn profile_has_file_ioctl_for_tty() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains("(allow file-ioctl"),
            "profile should allow file-ioctl for TTY devices (needed for setRawMode)"
        );
        assert!(profile.contains(r#"(literal "/dev/tty")"#));
    }

    #[test]
    fn profile_ssh_agent_carveout() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            Some(Path::new(
                "/Users/test/Library/Group Containers/2BUA8C4S2C.com.1password/t",
            )),
        )
        .unwrap();
        assert!(
            profile.contains(
                r#"(subpath "/Users/test/Library/Group Containers/2BUA8C4S2C.com.1password/t")"#
            ),
            "SSH agent dir should appear as a file-read carve-out"
        );
    }

    #[test]
    fn profile_no_security_server_mach_lookup() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            !profile.contains("com.apple.SecurityServer"),
            "SecurityServer Mach IPC should not be whitelisted (keychain bypass)"
        );
    }
}
