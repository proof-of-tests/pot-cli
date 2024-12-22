use assert_cmd::Command;

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}
