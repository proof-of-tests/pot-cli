use assert_cmd::Command;

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_valid_wasm_wat() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot.wasm")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Repository: https://github.com/proof-of-tests/pot-cli",
        ))
        .stdout(predicates::str::contains("test(i64) -> i64"));
}

// WAT files should be treated as wasm files
#[test]
fn test_valid_wat() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot.wat")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Repository: https://github.com/proof-of-tests/pot-cli",
        ))
        .stdout(predicates::str::contains("test(i64) -> i64"));
}

#[test]
fn test_no_repo() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot_no_repo.wat")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Invalid pot module: REPO global must be exported",
        ));
}

#[test]
fn test_no_memory() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot_no_memory.wat")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Invalid pot module: memory export not found",
        ));
}

#[test]
fn test_invalid_repo_utf8() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot_invalid_repo_utf8.wat")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Invalid pot module: REPO variable is not valid UTF-8",
        ));
}

#[test]
fn test_bad_test_type() {
    let mut cmd = Command::cargo_bin("pot-cli").unwrap();
    cmd.arg("info")
        .arg("tests/hello_pot_bad_test_type.wat")
        .assert()
        .failure();
}
