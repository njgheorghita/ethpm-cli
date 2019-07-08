import filecmp
import shutil

from ethpm import ASSETS_DIR
import pexpect

from ethpm_cli.constants import SOLC_INPUT, SOLC_OUTPUT


def test_custom_manifest_builder(tmp_path):
    tmp_projects_dir = tmp_path / "registry"
    tmp_projects_dir.mkdir()
    tmp_contracts_dir = tmp_projects_dir / "contracts"
    shutil.copytree(ASSETS_DIR / "registry" / "contracts", tmp_contracts_dir)
    shutil.copyfile(
        ASSETS_DIR / "registry" / SOLC_OUTPUT, tmp_projects_dir / SOLC_OUTPUT
    )
    child = pexpect.spawn(f"ethpm create --manifest --project-dir {tmp_projects_dir}")
    child.expect("EthPM CLI v0.1.0a0\r\n")
    child.expect("\r\n")
    child.expect("Manifest Creator\r\n")
    child.expect("----------------\r\n")
    child.expect("Create ethPM manifests for local projects.")
    child.expect("Project directory must include solc output.")
    child.expect("Follow steps in docs to generate solc output.")
    child.expect("\r\n")
    child.expect("Enter your package's name: ")
    child.sendline("wallet")
    child.expect("Enter your package's version: ")
    child.sendline("0.0.1")
    child.expect("Would you like to add a description to your package?")
    child.sendline("y")
    child.expect("Enter your description: ")
    child.sendline("This is a wallet package.")
    child.expect("Would you like to add a license to your package?")
    child.sendline("y")
    child.expect("Enter your license: ")
    child.sendline("MIT")
    child.expect("Would you like to add authors to your package?")
    child.sendline("y")
    child.expect("Enter an author, or multiple authors separated by commas: ")
    child.sendline("Paul, John, George, Ringo")
    child.expect("Would you like to add keywords to your package?")
    child.sendline("y")
    child.expect("Enter a keyword, or multiple keywords separated by commas: ")
    child.sendline("wallet, ethereum")
    child.expect(
        "Would you like to add links to the documentation, repo, or website in your package?"
    )
    child.sendline("y")
    child.expect("Enter a link for your documentation")
    child.sendline("www.readthedocs.com")
    child.expect("Enter a link for your repository")
    child.sendline("www.github.com")
    child.expect("Enter a link for your website")
    child.sendline("www.ethereum.org")
    child.expect("11 contract types available.\r\n")
    child.expect("\r\n")
    child.expect("AuthorityInterface\r\n")
    child.expect("Authorized\r\n")
    child.expect("AuthorizedInterface\r\n")
    child.expect("WhitelistAuthority\r\n")
    child.expect("WhitelistAuthorityInterface\r\n")
    child.expect("IndexedOrderedSetLib\r\n")
    child.expect("PackageDB\r\n")
    child.expect("PackageRegistry\r\n")
    child.expect("PackageRegistryInterface\r\n")
    child.expect("ReleaseDB\r\n")
    child.expect("ReleaseValidator.")
    child.expect("Would you like to include all available contract types?")
    child.sendline("y")
    child.expect("7 sources available.\r\n")
    child.expect("\r\n")
    child.expect("PackageRegistryInterface.sol\r\n")
    child.expect("PackageRegistry.sol\r\n")
    child.expect("PackageDB.sol\r\n")
    child.expect("ReleaseDB.sol\r\n")
    child.expect("Authority.sol\r\n")
    child.expect("ReleaseValidator.sol\r\n")
    child.expect("IndexedOrderedSetLib.sol.")
    child.expect("Would you like to include all available sources?")
    child.sendline("y")
    child.expect("Would you like to automatically inline all sources?")
    child.sendline("y")
    child.expect("Would you like to validate your manifest against the json schema?")
    child.sendline("y")
    child.expect(
        f"Manifest successfully created and written to {tmp_projects_dir}/0.0.1.json"
    )
    assert filecmp.cmp(
        ASSETS_DIR / "registry" / "0.0.1.json", tmp_projects_dir / "0.0.1.json"
    )


def test_basic_manifest_builder(tmp_path):
    tmp_projects_dir = tmp_path / "registry"
    tmp_projects_dir.mkdir()
    tmp_contracts_dir = tmp_projects_dir / "contracts"
    shutil.copytree(ASSETS_DIR / "registry" / "contracts", tmp_contracts_dir)
    shutil.copyfile(
        ASSETS_DIR / "registry" / SOLC_OUTPUT, tmp_projects_dir / SOLC_OUTPUT
    )
    child = pexpect.spawn(
        f"ethpm create --basic-manifest --project-dir {tmp_projects_dir} "
        "--package-name wallet --version 1.0.0"
    )
    child.expect("EthPM CLI v0.1.0a0\r\n")
    child.expect("\r\n")
    child.expect(
        f"Manifest successfully created and written to {tmp_projects_dir}/1.0.0.json"
    )


def test_create_solc_input(tmp_path):
    tmp_projects_dir = tmp_path / "registry"
    tmp_projects_dir.mkdir()
    tmp_contracts_dir = tmp_projects_dir / "contracts"
    shutil.copytree(ASSETS_DIR / "registry" / "contracts", tmp_contracts_dir)
    shutil.copyfile(ASSETS_DIR / "registry" / SOLC_INPUT, tmp_projects_dir / SOLC_INPUT)
    child = pexpect.spawn(f"ethpm create --solc-input --project-dir {tmp_projects_dir}")
    child.expect("EthPM CLI v0.1.0a0\r\n")
    child.expect("\r\n")
    child.expect(
        "Solidity compiler input successfully created and "
        f"written to {tmp_projects_dir}/{SOLC_INPUT}"
    )
