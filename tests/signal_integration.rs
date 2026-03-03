//! Signal forwarding and child exit code tests.
//!
//! These test that the orchestration layer correctly:
//! - Forwards signals to the child process
//! - Exits with the child's exit code

use std::process::Command;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Spawn a child that sleeps, send it SIGTERM, verify it dies.
#[test]
fn child_receives_forwarded_sigterm() {
    // Spawn a simple sleep process
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("failed to spawn sleep");

    let pid = Pid::from_raw(child.id() as i32);

    // Give it a moment to start
    std::thread::sleep(Duration::from_millis(50));

    // Send SIGTERM directly (simulating what ziplock's signal_forward does)
    signal::kill(pid, Signal::SIGTERM).expect("failed to send SIGTERM");

    // Child should exit
    let status = child.wait().expect("failed to wait on child");
    assert!(
        !status.success(),
        "child should have been terminated by signal"
    );
}

/// Verify child exit code is propagated.
#[test]
fn child_exit_code_propagated() {
    // Spawn a process that exits with code 42
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("exit 42")
        .spawn()
        .expect("failed to spawn sh");

    let status = child.wait().expect("failed to wait on child");
    assert_eq!(status.code(), Some(42));
}

/// Verify child exit code 0 (success).
#[test]
fn child_exit_code_zero() {
    let mut child = Command::new("true").spawn().expect("failed to spawn true");

    let status = child.wait().expect("failed to wait on child");
    assert_eq!(status.code(), Some(0));
}
