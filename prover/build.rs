use std::process::Command;
use std::str;

fn main() {
    // 获取最近的 commit hash
    let output = Command::new("git")
        .arg("describe")
        .arg("--tags")
        .arg("--long")
        .output()
        .expect("Failed to execute git command");

    let version = str::from_utf8(&output.stdout).expect("Failed to parse output");

    // 获取最近的 commit 时间戳
    let output = Command::new("git")
        .arg("log")
        .arg("-1")
        .arg("--format=%ct")
        .output()
        .expect("Failed to execute git command");

    let commit_timestamp = str::from_utf8(&output.stdout).expect("Failed to parse output");

    let version = format!("{}-t{}", version.trim(), commit_timestamp.trim());
    println!("cargo:rustc-env=ZKEVM_GIT_VERSION={}", version)
}
