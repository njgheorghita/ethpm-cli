import pexpect

from ethpm_cli.constants import ETHPM_CLI_VERSION


def test_examine_owned_manifest(tmp_project_dir):
    child = pexpect.spawn(
        f"ethpm examine --manifest-path {tmp_project_dir / 'owned.json'}", timeout=5
    )
    child.expect(f"ethPM CLI v{ETHPM_CLI_VERSION}\r\n")
    child.expect("\r\n")
    child.expect("Package Name: owned\r\n")
    child.expect("Package Version: 1.0.0\r\n")
    child.expect("Manifest Version: 2\r\n")
    child.expect("\r\n")
    child.expect("Sources: \r\n")
    child.expect(
        "./contracts/Owned.sol: ipfs://Qme4otpS88NV8yQi8TfTP89EsQC5bko3F5N1yhRoi6c\r\n"
    )
    child.expect("\r\n")
    child.expect("Contract Types: \r\n")
    child.expect("No contract types found.\r\n")
    child.expect("\r\n")
    child.expect("Deployments: \r\n")
    child.expect("No deployments found.\r\n")
    child.expect("\r\n")
    child.expect("Build Dependencies: \r\n")
    child.expect("No build dependencies found.\r\n")
    child.expect("\r\n")


def test_examine_dai_manifest(tmp_project_dir):
    child = pexpect.spawn(
        f"ethpm examine --manifest-path {tmp_project_dir / 'dai.json'}", timeout=5
    )
    child.expect(f"ethPM CLI v{ETHPM_CLI_VERSION}\r\n")
    child.expect("\r\n")
    child.expect("Package Name: dai\r\n")
    child.expect("Package Version: 1.0.0\r\n")
    child.expect("Manifest Version: 2\r\n")
    child.expect("\r\n")
    child.expect("Sources: \r\n")
    child.expect(r"./DSToken.sol: pragma solidity \^0.4.13;    ////// lib/ds-math/src")
    child.expect("\r\n")
    child.expect("Contract Types: \r\n")
    child.expect("DSToken: ['abi', 'compiler', 'runtime_bytecode']")
    child.expect("\r\n")
    child.expect("Deployments: \r\n")
    child.expect(
        "blockchain://d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3/"
    )
    child.expect(
        "block/375a50b1764960bde8df83fa1e807f4addfa99a1e19b10f2a5e8b36b32abe54d\r\n"
    )
    child.expect(
        "- DSToken @ 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359 :: DSToken\r\n"
    )
    child.expect("\r\n")
    child.expect("Build Dependencies: \r\n")
    child.expect("No build dependencies found.\r\n")
    child.expect("\r\n")
