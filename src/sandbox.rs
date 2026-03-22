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
    // Reject characters that could break out of an SBPL string literal or
    // corrupt the profile: `"` terminates the literal, `\` is the escape
    // character, and control characters (including \n, \r) may cause
    // unpredictable parser behaviour or allow rule injection.
    if s.contains('"') || s.contains('\\') || s.chars().any(|c| c.is_control()) {
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
        // Canonicalize to resolve symlinks before interpolating into the SBPL profile.
        // A symlink like /tmp/link -> ~/Library would otherwise bypass the ~/Library deny rule.
        let canonical = std::fs::canonicalize(path).with_context(|| {
            format!(
                "--allow-path '{}' could not be canonicalized (does it exist?)",
                path.display()
            )
        })?;
        let safe = sanitize_sbpl_path(&canonical)?;
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
;; Enumerate process-exec ops explicitly; process-exec-interpreter is required
;; for hashbang scripts (e.g. npm lifecycle hooks invoking #!/usr/bin/env node).
(allow process-exec)
(allow process-exec-interpreter)
(allow process-fork)
(allow process-info*)
(allow process-codesigning*)
(allow signal (target same-sandbox))

;; ── File reads: allow most, deny sensitive system trees ──────────────────
(allow file-read*)

;; Deny sensitive system locations
(deny file-read*
    (subpath "{home_str}/Library")
    (subpath "/Library")
    (subpath "/System"))

;; Carve-outs: system frameworks, developer tools, and ~/Library subtrees.
;; literal "~/Library": codesign (via AMFI) checks file-read-data on ancestor
;; directories; ~/Library itself must be readable or codesign refuses to sign
;; any ~/Library/* file. `literal` matches only the exact path, not its contents.
(allow file-read*
    (literal "{home_str}/Library")
    (subpath "/System/Library/Frameworks")
    (subpath "/System/Library/PrivateFrameworks")
    (subpath "/System/Library/dyld")
    (subpath "/System/Library/CoreServices")
    (subpath "/System/Library/Perl")
    (subpath "/System/Library/OpenSSL")
    (subpath "/System/Library/Sandbox")
    (subpath "/System/Library/AssetsV2")
    (subpath "/Library/Frameworks")
    (subpath "/Library/Developer")
    (subpath "/Library/Apple")
    (subpath "/Library/Preferences")
    (subpath "/Library/Keychains")
    (subpath "/Library/Security")
    (subpath "{home_str}/Library/Preferences")
    (subpath "{home_str}/Library/Caches")
    (subpath "{home_str}/Library/Keychains")
    (subpath "{home_str}/Library/Developer")
    (subpath "{home_str}/Library/org.swift.swiftpm")
    (subpath "{home_str}/Library/Security")
{ssh_agent_rule})

;; On macOS 11+, /bin, /usr, and /sbin are firmlinks into /System/Volumes/Root.
;; The kernel resolves firmlinks before evaluating sandbox subpath rules, so the
;; (deny file-read* (subpath "/System")) rule above blocks /bin/cat, /usr/bin/grep,
;; etc. Re-allow these standard Unix paths explicitly (last-match-wins in SBPL).
(allow file-read* process-exec
    (subpath "/bin")
    (subpath "/usr/bin")
    (subpath "/usr/lib")
    (subpath "/usr/libexec")
    (subpath "/usr/share")
    (subpath "/sbin")
    (subpath "/usr/sbin")
    ;; Homebrew: /opt/homebrew on Apple Silicon, /usr/local on Intel
    (subpath "/opt/homebrew")
    (subpath "/usr/local"))

;; ── File writes (includes file-clone and file-link) ────────────────────────
;; file-clone (clonefile APFS CoW, used by xcodebuild builtin-copy) and
;; file-link (hard links) share the same path policy as file-write*. All three
;; ops are listed together so the allow/deny/carve-out structure only exists once.
;;
;; /private/tmp: temp files (symlink /tmp -> /private/tmp; kernel resolves before
;;   SBPL so only the canonical path is needed).
;; /private/var/folders: per-user temp tree. Narrowed from /private/var to avoid
;;   granting write access to /private/var/db, /private/var/log, etc.
(allow file-write* file-clone file-link
    (subpath "{cwd_str}")
    (subpath "{home_str}")
    (subpath "/private/tmp")
    (subpath "/private/var/folders")
{extra_write_rules})
;; Block writes/clones/links into the sensitive ~/Library subtree.
(deny file-write* file-clone file-link
    (subpath "{home_str}/Library"))
;; Re-allow specific ~/Library subtrees.
;; - literal "~/Library": the directory ENTRY itself (not its contents).
;;   codesign (via AMFI) calls sandbox_check() on every ancestor before signing;
;;   if ~/Library itself is denied for file-write-data, codesign refuses to sign
;;   any ~/Library/* file. `literal` matches only the exact path.
;; - Caches: build tools (Go, npm, pip, Homebrew, Xcode).
;; - Keychains: OAuth token storage for Claude Code login.
;; - Developer: xcodebuild DerivedData, CoreSimulator, Xcode archives.
;; - org.swift.swiftpm: Swift Package Manager package cache.
(allow file-write* file-clone file-link
    (literal "{home_str}/Library")
    (subpath "{home_str}/Library/Caches")
    (subpath "{home_str}/Library/Keychains")
    (subpath "{home_str}/Library/Developer")
    (subpath "{home_str}/Library/org.swift.swiftpm"))

;; ── Network ──────────────────────────────────────────────────────────────
{network_rules}

;; ── Mach / XPC IPC ──────────────────────────────────────────────────────
;; Explicit allowlist instead of bare (allow mach-lookup). Eliminates ~70
;; irrelevant GUI, media, Bluetooth, Siri, iCloud, and phone services from
;; the App Store baseline, removing them as potential pivot points for
;; mach IPC sandbox escapes (CVE-2018-4280, CVE-2025-31258, et al.).
;;
;; Sources: application.sb baseline, appsandbox-common.sb, com.apple.mtlcompilerservice.sb,
;; swift-package embedded profile, IconServices framework.sb, and empirical requirements
;; for Claude Code (Bun runtime) + xcodebuild/codesign/simulator workflows.
;;
;; If a new tool needs a service not listed here, the symptom is a silent hang
;; or EPERM from a framework call. Add the service and document why.
(allow mach-lookup
    ;; ── Core OS ─────────────────────────────────────────────────────────
    ;; Preferences (NSUserDefaults, CFPreferences — used by virtually everything)
    (global-name "com.apple.cfprefsd.agent")
    (global-name "com.apple.cfprefsd.daemon")
    ;; Distributed notifications (NSDistributedNotificationCenter, framework delivery)
    (global-name "com.apple.distributed_notifications@Uv3")
    (global-name "com.apple.distributed_notifications@1v3")
    (global-name "com.apple.system.notification_center")
    ;; System logging (os_log, NSLog, used by all Apple frameworks)
    (global-name "com.apple.logd")
    (global-name "com.apple.logd.admin")
    (global-name "com.apple.logd.events")
    ;; File system events (used by build tools, LSP watchers, editors)
    (global-name "com.apple.FSEvents")
    ;; File coordination (NSFileCoordinator — used by Xcode build system)
    (global-name "com.apple.FileCoordination")
    ;; Disk arbitration (volume mount/unmount events)
    (global-name "com.apple.DiskArbitration.diskarbitrationd")
    ;; Spotlight metadata (MDItem APIs used by some build tools)
    (global-name "com.apple.metadata.mds")
    ;; Process lifecycle assertions (used by xcodebuild to prevent sleep during builds)
    (global-name "com.apple.runningboard")
    ;; Hang reporter (used by xcodebuild for build diagnostics)
    (global-name "com.apple.spindump")
    ;; ── Security / keychain ─────────────────────────────────────────────
    ;; SecurityServer: keychain API (SecItemAdd/CopyMatching), authorization,
    ;;   code signing. Required for Claude Code OAuth token storage and codesign.
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.securityd.xpc")
    ;; OCSP certificate validation (TLS cert revocation checks)
    (global-name "com.apple.ocspd")
    ;; Certificate trust evaluation (TLS, code signing trust chains)
    (global-name "com.apple.TrustEvaluationAgent")
    (global-name "com.apple.trustd.agent")
    (global-name "com.apple.security.pboxd")
    ;; Gatekeeper / notarization exec policy (checked by SWBBuildService during codesign)
    (global-name "com.apple.security.syspolicy.exec")
    ;; GSS/Kerberos (used by git with GSSAPI and some corporate auth schemes)
    (global-name "com.apple.GSSCred")
    (global-name "com.apple.KerberosHelper.LKDCHelper")
    (global-name "org.h5l.kcm")
    ;; TCC (privacy permission checks: file access, network, etc.)
    (global-name "com.apple.tccd")
    (global-name "com.apple.tccd.system")
    ;; ── Directory services ───────────────────────────────────────────────
    ;; User/group name lookups: getpwuid(), NSUserName(), NSHomeDirectory(), group membership
    (global-name "com.apple.system.opendirectoryd.api")
    (global-name "com.apple.system.opendirectoryd.libinfo")
    (global-name "com.apple.system.opendirectoryd.membership")
    (global-name "com.apple.system.DirectoryService.membership_v1")
    ;; BSD per-user temp directory helper (creates/resolves $TMPDIR paths under /var/folders)
    (global-name "com.apple.bsd.dirhelper")
    ;; ── Launch Services / CoreServices ───────────────────────────────────
    ;; Used by codesign, xcodebuild, and many Apple frameworks internally
    (global-name "com.apple.CoreServices.coreservicesd")
    (global-name "com.apple.coreservices.launchservicesd")
    (global-name "com.apple.coreservices.launcherror-handler")
    (global-name "com.apple.coreservices.quarantine-resolver")
    (global-name "com.apple.coreservices.appleevents")
    ;; Launch Services DB (required by codesign and xcodebuild path resolution)
    (global-name "com.apple.lsd.mapdb")
    (global-name "com.apple.lookupd")
    (global-name "com.apple.logind")
    (global-name "com.apple.xpc.loginitemregisterd")
    (global-name "com.apple.xpc.smd")
    ;; ── Network config ───────────────────────────────────────────────────
    ;; Network interface/routing info (used by curl, git, npm, etc.)
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.SystemConfiguration.DNSConfiguration")
    (global-name "com.apple.SystemConfiguration.NetworkInformation")
    (global-name "com.apple.SystemConfiguration.helper")
    ;; Network extension (used by VPN/proxy clients and system network stack)
    (global-name "com.apple.nehelper")
    (global-name "com.apple.nesessionmanager")
    ;; ── Fonts ────────────────────────────────────────────────────────────
    ;; Terminal rendering and xcodebuild asset processing
    (global-name "com.apple.fonts")
    (global-name "com.apple.FontObjectsServer")
    (global-name "com.apple.FontRegistry.FontRegistryUIAgent")
    ;; ── Developer tools ──────────────────────────────────────────────────
    ;; Platform SDK asset downloads (required by swift-package and xcodebuild)
    (global-name "com.apple.mobileassetd.v2")
    ;; Icon services (used by xcodebuild when processing asset catalogs)
    (global-name "com.apple.iconservices")
    (global-name "com.apple.iconservices.store")
    ;; CoreSimulator: simulator lifecycle, process launch, and runtime disk images
    (global-name "com.apple.containermanagerd")
    (global-name "com.apple.CoreSimulator.simdiskimaged")
    (global-name "com.apple.CoreSimulator.CoreSimulatorService")
    (global-name "com.apple.CoreSimulator.SimLaunchHost-arm64")
    ;; CoreDevice: Xcode 15+ physical device connectivity (deploy/debug on device)
    (global-name "com.apple.CoreDevice.CoreDeviceService")
    ;; XCTest runner (required for xcodebuild test on simulator and device)
    (global-name "com.apple.testmanagerd")
    (global-name "com.apple.testmanagerd.control")
    ;; Power management activity assertions (xcodebuild holds a build activity assertion)
    (global-name "com.apple.PowerManagement.control")
    ;; Time Machine exclusion registration (xcodebuild registers DerivedData as TM-excluded)
    (global-name "com.apple.backupd.sandbox.xpc")
    ;; GPU/Metal compiler service (used by xcodebuild for Metal shader compilation)
    (global-name "com.apple.cvmsServ")
    ;; PluginKit (Xcode extensions and build tool plugins)
    (global-name "com.apple.pluginkit.pkd")
    ;; ── Diagnostics / analytics ──────────────────────────────────────────
    ;; Required by many Apple frameworks and tools (crashes, metrics, build analytics)
    (global-name "com.apple.analyticsd")
    (global-name "com.apple.diagnosticd")
    (global-name "com.apple.rtcreportingd")
    (global-name "com.apple.powerlog.plxpclogger.xpc")
    ;; ── Input method ─────────────────────────────────────────────────────
    ;; Terminal keyboard input (input method selection, IME services)
    (global-name "com.apple.inputmethodkit.getxpcendpoint")
    (global-name "com.apple.inputmethodkit.launchagent")
    (global-name "com.apple.inputmethodkit.launcher"))
(allow mach-register)
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
(allow sysctl-read)
(allow iokit*)
(allow ipc*)
(allow user-preference*)
(allow system-socket)
(allow darwin-notification-post)
;; lsopen is required for Claude Code's OAuth browser launch (login flow).
;; Residual risk: a prompt injection could open a browser to an attacker URL.
;; Mitigated by: DNS proxy blocks malware/phishing domains; browser runs in
;; its own App Sandbox; no capability to write+execute in the same step.
(allow lsopen)
;; Note: /bin/ps and /usr/bin/top are setuid-root binaries — the macOS sandbox blocks
;; setuid execution unconditionally regardless of SBPL rules. process-info* (declared
;; above in the Process section) still benefits non-setuid tools and Node.js APIs
;; that call proc_pidinfo() directly (e.g. process.cpuUsage(), os.loadavg()).

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

    // Ensure standard macOS paths are in PATH so subprocesses (shells spawned by Claude)
    // can find tools like /usr/bin/head, /bin/mkdir, etc. Subprocess shells started
    // non-interactively don't source /etc/profile, so they may inherit a stripped PATH.
    let standard_paths = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin";
    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = if current_path.is_empty() {
        standard_paths.to_string()
    } else {
        // Append standard paths not already present
        let mut parts: Vec<&str> = current_path.split(':').collect();
        for p in standard_paths.split(':') {
            if !parts.contains(&p) {
                parts.push(p);
            }
        }
        parts.join(":")
    };
    cmd.env("PATH", new_path);

    // SPM uses sandbox-exec to sandbox swiftc when compiling Package.swift manifests,
    // and also wraps certain build steps. sandbox-exec calls sandbox_apply() which is
    // blocked inside ziplock's SBPL profile (no valid SBPL op name allows it selectively).
    // Disable SPM's own sandboxing — ziplock's sandbox already constrains the process tree.
    //
    // XBS_DISABLE_SANDBOXED_BUILDS=1 — disables build-phase sandbox-exec (xcodebuild).
    // SWIFTPM_SANDBOX=0 — disables sandboxing in open-source SPM toolchains.
    //
    // IDEPackageSupportDisableManifestSandbox is NOT set here — it is an NSUserDefaults key
    // that xcodebuild reads from ~/Library/Preferences/com.apple.dt.Xcode.plist.  There is
    // no per-process mechanism to override NSUserDefaults without writing that plist, which
    // would persist beyond ziplock's lifetime and affect Xcode sessions outside the sandbox.
    // If you run Xcode-managed SPM builds inside ziplock, set this once manually:
    //   defaults write com.apple.dt.Xcode IDEPackageSupportDisableManifestSandbox -bool YES
    cmd.env("XBS_DISABLE_SANDBOXED_BUILDS", "1");
    cmd.env("SWIFTPM_SANDBOX", "0");

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
        use std::fs;
        // Use real temp dirs so canonicalize() succeeds.
        let dir1 = std::env::temp_dir().join("ziplock_test_allow_a");
        let dir2 = std::env::temp_dir().join("ziplock_test_allow_b");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();
        let canonical1 = fs::canonicalize(&dir1).unwrap();
        let canonical2 = fs::canonicalize(&dir2).unwrap();

        let profile = generate_profile(
            Path::new("/tmp"),
            Path::new("/Users/test"),
            &[dir1, dir2],
            false,
            None,
        )
        .unwrap();
        assert!(profile.contains(&format!(r#"(subpath "{}")"#, canonical1.display())));
        assert!(profile.contains(&format!(r#"(subpath "{}")"#, canonical2.display())));
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
    fn profile_rejects_path_with_control_chars() {
        // A newline embedded in a path could inject SBPL rules after the string literal
        let result = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[PathBuf::from("/tmp/evil\n)(allow network-outbound")],
            false,
            None,
        );
        assert!(
            result.is_err(),
            "path with embedded newline should be rejected"
        );

        let result2 = generate_profile(
            Path::new("/tmp/proj\r(allow network-outbound)"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        );
        assert!(result2.is_err(), "cwd with embedded CR should be rejected");
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
    fn profile_allows_process_info_for_monitoring_tools() {
        // process-info* permits proc_pidinfo() calls (used by ps, top, htop).
        // Note: /bin/ps and /usr/bin/top are setuid-root binaries; the macOS sandbox
        // blocks execution of setuid binaries unconditionally regardless of the SBPL
        // profile. process-info* still benefits non-setuid tools and Node.js APIs
        // that call proc_pidinfo() directly (e.g. os.loadavg(), process.cpuUsage()).
        // The correct prefix is "process-info" — "proc-info" is an unbound SBPL variable.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains("(allow process-info*)"),
            "profile must contain (allow process-info*) for ps/top/htop support"
        );
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
    fn profile_allows_standard_unix_paths_after_system_deny() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        // /bin, /usr/bin, etc. are firmlinks into /System/Volumes/Root on macOS 11+.
        // They must be explicitly re-allowed after the (deny file-read* (subpath "/System")) rule.
        let deny_system_pos = profile.find(r#"(subpath "/System")"#).unwrap();
        for path in &[
            "/bin",
            "/usr/bin",
            "/usr/lib",
            "/usr/libexec",
            "/usr/share",
            "/sbin",
            "/usr/sbin",
        ] {
            let rule = format!(r#"(subpath "{path}")"#);
            let allow_pos = profile
                .rfind(&rule)
                .unwrap_or_else(|| panic!("{rule} missing from profile"));
            assert!(
                allow_pos > deny_system_pos,
                "{rule} carve-out must appear after (deny file-read* (subpath \"/System\"))"
            );
        }
    }

    #[test]
    fn profile_allows_homebrew_exec() {
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        // npm lifecycle scripts spawn binaries from Homebrew; both paths must be
        // allowed for process-exec so node, npm, python, etc. can be spawned.
        assert!(profile.contains(r#"(subpath "/opt/homebrew")"#));
        assert!(profile.contains(r#"(subpath "/usr/local")"#));
    }

    #[test]
    fn profile_allows_process_codesigning() {
        // process-codesigning* is required for `codesign --sign -` (ad-hoc signing),
        // which xcodebuild runs when building frameworks and dylibs for simulators.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains("(allow process-codesigning*)"),
            "profile must allow process-codesigning* for xcodebuild ad-hoc signing"
        );
    }

    #[test]
    fn profile_has_system_assetsv2_carveout() {
        // /System/Library/AssetsV2 contains Metal Toolchain cryptex volumes.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/System/Library/AssetsV2")"#),
            "profile must allow reads to /System/Library/AssetsV2 for Metal Toolchain"
        );
    }

    #[test]
    fn profile_has_system_keychains_carveout() {
        // /Library/Keychains is read by SecItemCopyMatching (xcodebuild, gh, etc.)
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/Library/Keychains")"#),
            "profile must allow reads to /Library/Keychains for SecItemCopyMatching"
        );
    }

    #[test]
    fn profile_has_swift_package_manager_carveout() {
        // ~/Library/org.swift.swiftpm must be read+write for Swift Package Manager.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/Users/test/Library/org.swift.swiftpm")"#),
            "profile must have ~/Library/org.swift.swiftpm carve-out for Swift Package Manager"
        );
        // Write carve-out must appear after the ~/Library write deny
        let deny_pos = profile.find(r#"(deny file-write*"#).unwrap();
        let spm_write_pos = profile
            .rfind(r#"(subpath "/Users/test/Library/org.swift.swiftpm")"#)
            .unwrap();
        assert!(
            spm_write_pos > deny_pos,
            "org.swift.swiftpm write carve-out must appear after ~/Library write deny"
        );
    }

    #[test]
    fn profile_allows_file_clone_and_link() {
        // file-clone allows clonefile() (APFS copy-on-write) used by builtin-copy
        // in xcodebuild when copying .bundle targets between DerivedData paths.
        // file-link allows hard link creation (link() syscall).
        // NOTE: file-clone* and file-link* (with wildcard) are INVALID SBPL and
        // cause "unbound variable" at sandbox_init time — use the bare op names.
        //
        // These operations must be PATH-SCOPED to match the file-write* carve-outs.
        // A bare (allow file-clone) without a path filter bypasses (deny file-write*
        // ~/Library) — allowing clonefile() or link() into ~/Library/LaunchAgents etc.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        // file-write*, file-clone, and file-link are listed together in each rule.
        assert!(
            profile.contains("(allow file-write* file-clone file-link"),
            "profile must allow file-write* file-clone file-link together"
        );
        assert!(
            profile.contains(r#"(subpath "/Users/test/Library/Developer")"#),
            "file-clone/file-link must reach ~/Library/Developer for xcodebuild"
        );
        // Must deny all three ops in ~/Library
        assert!(
            profile.contains("(deny file-write* file-clone file-link"),
            "profile must deny file-write* file-clone file-link in ~/Library"
        );
        let deny_pos = profile
            .find("(deny file-write* file-clone file-link")
            .unwrap();
        let allow_carveout_pos = profile
            .rfind("(allow file-write* file-clone file-link")
            .unwrap();
        assert!(
            allow_carveout_pos > deny_pos,
            "file-clone/file-link carve-outs must appear after the ~/Library deny"
        );
        // Wildcards must NOT be used — they are invalid SBPL
        assert!(
            !profile.contains("file-clone*"),
            "use file-clone not file-clone* (wildcard is invalid SBPL)"
        );
        assert!(
            !profile.contains("file-link*"),
            "use file-link not file-link* (wildcard is invalid SBPL)"
        );
    }

    #[test]
    fn profile_file_clone_cannot_reach_library_launchagents() {
        // A bare (allow file-clone) without path filters lets a sandboxed process
        // clonefile() into ~/Library/LaunchAgents even though file-write* is denied there.
        // Verify the deny rule is present and positioned correctly.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        // The ~/Library deny must cover file-write*, file-clone, and file-link together
        assert!(
            profile.contains("(deny file-write* file-clone file-link"),
            "profile must deny file-write* file-clone file-link to ~/Library"
        );
        let clone_deny_pos = profile
            .find("(deny file-write* file-clone file-link")
            .unwrap();
        // ~/Library/LaunchAgents must not appear as a carve-out
        assert!(
            !profile.contains("LaunchAgents"),
            "~/Library/LaunchAgents must never be a file-clone/file-link carve-out"
        );
        // The combined deny must appear before the carve-out allows (last-match-wins)
        let carveout_pos = profile
            .rfind("(allow file-write* file-clone file-link")
            .unwrap();
        assert!(
            carveout_pos > clone_deny_pos,
            "file-write*/file-clone/file-link carve-outs must follow the ~/Library deny"
        );
    }

    #[test]
    fn profile_has_security_carveout_for_codesign() {
        // codesign --sign - uses sandbox_check() against ~/Library/Security and
        // /Library/Security (trust settings) before signing. Without these carve-outs
        // the check returns EPERM silently (sandbox_check doesn't log violations).
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/Library/Security")"#),
            "profile must allow reads to /Library/Security for codesign trust settings"
        );
        assert!(
            profile.contains(r#"(subpath "/Users/test/Library/Security")"#),
            "profile must allow reads to ~/Library/Security for codesign trust settings"
        );
        // Both carve-outs must appear after the deny rules (last-match-wins)
        let deny_pos = profile.find(r#"(deny file-read*"#).unwrap();
        let lib_sec_pos = profile.rfind(r#"(subpath "/Library/Security")"#).unwrap();
        let home_sec_pos = profile
            .rfind(r#"(subpath "/Users/test/Library/Security")"#)
            .unwrap();
        assert!(
            lib_sec_pos > deny_pos,
            "/Library/Security carve-out must follow deny"
        );
        assert!(
            home_sec_pos > deny_pos,
            "~/Library/Security carve-out must follow deny"
        );
    }

    #[test]
    fn profile_has_library_dir_literal_for_codesign() {
        // codesign walks ancestor directories and calls sandbox_check() with file-read-data
        // and file-write-data on each ancestor. If ~/Library itself is denied for either,
        // codesign refuses to sign ANY file under ~/Library/* with "Operation not permitted".
        // The fix: allow ~/Library as a literal (exact path only) so the directory entry
        // is accessible, while subpath deny still blocks all files/subdirs within ~/Library.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        let literal = r#"(literal "/Users/test/Library")"#;
        // Literal must appear in both a file-read* and file-write* allow block
        assert!(
            profile.contains(literal),
            "profile must contain ~/Library literal for codesign ancestor check"
        );
        // Must appear AFTER both deny rules (last-match-wins)
        let read_deny_pos = profile.find(r#"(deny file-read*"#).unwrap();
        let write_deny_pos = profile.find(r#"(deny file-write*"#).unwrap();
        let first_lit_pos = profile.find(literal).unwrap();
        assert!(
            first_lit_pos > read_deny_pos,
            "~/Library literal must follow deny file-read* rule"
        );
        // Write literal appears in a later block — use rfind for the write occurrence
        let last_lit_pos = profile.rfind(literal).unwrap();
        assert!(
            last_lit_pos > write_deny_pos,
            "~/Library literal must follow deny file-write* rule"
        );
        // Subpath deny must still be present (protects ~/Library contents)
        assert!(
            profile.contains(r#"(subpath "/Users/test/Library")"#),
            "profile must still deny file-read/write on ~/Library subpath"
        );
    }

    #[test]
    fn profile_write_tmp_uses_canonical_path() {
        // /tmp is a symlink to /private/tmp; the kernel resolves symlinks before SBPL
        // matching, so (subpath "/tmp") would never actually match — only /private/tmp is
        // needed. Redundant rules add noise and obscure the actual scope.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/private/tmp")"#),
            "profile must allow writes to /private/tmp"
        );
        assert!(
            !profile.contains(r#"(subpath "/tmp")"#),
            "redundant /tmp rule should be absent (kernel resolves to /private/tmp)"
        );
    }

    #[test]
    fn profile_write_var_narrowed_to_folders() {
        // Write access to /private/var is scoped to /private/var/folders (the per-user
        // temp directory tree). Granting /private/var would include /private/var/db,
        // /private/var/log, etc. — root-owned in practice but unnecessarily broad.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains(r#"(subpath "/private/var/folders")"#),
            "profile must allow writes to /private/var/folders"
        );
        assert!(
            !profile.contains(r#"(subpath "/private/var")"#),
            "broad /private/var write must be absent; use /private/var/folders"
        );
        assert!(
            !profile.contains(r#"(subpath "/var")"#),
            "redundant /var rule should be absent (kernel resolves to /private/var)"
        );
    }

    #[test]
    fn profile_excludes_mach_priv_ports() {
        // mach-priv-host-port and mach-priv-task-port grant host-level privilege port
        // access, which is more powerful than required. Developer tools only need
        // mach-lookup/mach-register for bootstrap service access.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            !profile.contains("mach-priv-host-port"),
            "profile must not grant mach-priv-host-port (excessive privilege)"
        );
        assert!(
            !profile.contains("mach-priv-task-port"),
            "profile must not grant mach-priv-task-port (excessive privilege)"
        );
    }

    #[test]
    fn profile_allows_lsopen_for_auth() {
        // lsopen is required for Claude Code's OAuth login flow: it opens the browser
        // to the authentication URL via LaunchServices. Removed in v1.2.0; restored in
        // v1.3.2 after confirming that the login flow silently breaks without it.
        // Residual risk (arbitrary app launch via prompt injection) is mitigated by the
        // DNS proxy blocking malicious domains and browsers running in their own sandbox.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains("(allow lsopen)"),
            "profile must allow lsopen (required for Claude Code OAuth browser launch)"
        );
    }

    #[test]
    fn profile_sysctl_read_only() {
        // sysctl-read is sufficient for Claude Code's needs (checking hw.machine,
        // kern.osproductversion, etc.). sysctl* would also grant write access,
        // which is unnecessary and broader than required.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            profile.contains("(allow sysctl-read)"),
            "profile must use sysctl-read (not sysctl*)"
        );
        assert!(
            !profile.contains("(allow sysctl*)"),
            "profile must not use sysctl* (grants unnecessary sysctl write access)"
        );
    }

    #[test]
    fn profile_mach_lookup_is_allowlisted_not_bare() {
        // Bare (allow mach-lookup) without global-name filters exposes every Mach
        // service on the system as a potential sandbox escape pivot (CVE-2018-4280,
        // CVE-2025-31258, jhftss 10+ vulns research). The profile must use an explicit
        // allowlist so GUI, media, Bluetooth, Siri, and iCloud services are unreachable.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(
            !profile.contains("(allow mach-lookup)\n"),
            "bare (allow mach-lookup) must not appear — use global-name allowlist"
        );
        assert!(
            profile.contains("(allow mach-lookup\n"),
            "profile must have a filtered (allow mach-lookup ...) block"
        );
    }

    #[test]
    fn profile_mach_allowlist_contains_required_services() {
        // Core services needed by Claude Code (Bun runtime) and developer tools.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        let required = [
            // Security / keychain (Claude Code OAuth tokens, codesign)
            "com.apple.SecurityServer",
            "com.apple.securityd.xpc",
            "com.apple.ocspd",
            "com.apple.TrustEvaluationAgent",
            // Preferences (NSUserDefaults — used by every framework)
            "com.apple.cfprefsd.agent",
            "com.apple.cfprefsd.daemon",
            // Logging
            "com.apple.logd",
            // Network config (curl, git, npm)
            "com.apple.SystemConfiguration.configd",
            "com.apple.SystemConfiguration.DNSConfiguration",
            // Developer tools
            "com.apple.lsd.mapdb",
            "com.apple.mobileassetd.v2",
            "com.apple.iconservices",
            "com.apple.containermanagerd",
            "com.apple.CoreSimulator.simdiskimaged",
            "com.apple.cvmsServ",
        ];
        for svc in &required {
            assert!(
                profile.contains(svc),
                "required mach service missing from allowlist: {svc}"
            );
        }
    }

    #[test]
    fn profile_mach_allowlist_excludes_gui_media_icloud() {
        // These services are irrelevant to a CLI/TUI tool and are excluded to
        // reduce the attack surface for mach IPC sandbox escapes.
        let profile = generate_profile(
            Path::new("/tmp/proj"),
            Path::new("/Users/test"),
            &[],
            false,
            None,
        )
        .unwrap();
        let excluded = [
            // Window server — Claude Code is a CLI tool, no GUI rendering
            "com.apple.windowserver.active",
            "com.apple.CARenderServer",
            "com.apple.windowmanager.server",
            "com.apple.dock.server",
            // Bluetooth — not needed
            "com.apple.BluetoothServices",
            // Siri / speech
            "com.apple.assistant.analytics",
            "com.apple.speechArbitrationServer",
            // iCloud sync
            "com.apple.bird",
            "com.apple.kvsd",
            // Media
            "com.apple.mediaremoted.xpc",
            "com.apple.midiserver",
            // Phone / FaceTime
            "com.apple.telephonyutilities.callservicesdaemon.voip",
            "PurplePPTServer",
            // Photos
            "com.apple.photos.service",
        ];
        for svc in &excluded {
            assert!(
                !profile.contains(svc),
                "GUI/media/iCloud service must not be in mach allowlist: {svc}"
            );
        }
    }
}
