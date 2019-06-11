from argparse import Namespace
import json
import os
from pathlib import Path

from eth_typing import URI, Address
from eth_utils import is_hex_address
from ethpm.exceptions import ValidationError as EthPMValidationError
from ethpm.utils.ipfs import is_ipfs_uri
from ethpm.utils.uri import is_valid_content_addressed_github_uri
from ethpm.validation import is_valid_registry_uri, validate_package_name
from web3 import Web3

from ethpm_cli._utils.ethpmdir import is_package_installed
from ethpm_cli.config import Config
from ethpm_cli.constants import ETHERSCAN_KEY_ENV_VAR
from ethpm_cli.exceptions import EtherscanKeyNotFound, InstallError, UriNotSupportedError, ValidationError


def validate_parent_directory(parent_dir: Path, child_dir: Path) -> None:
    if parent_dir not in child_dir.parents:
        raise InstallError(f"{parent_dir} was not found in {child_dir} directory tree.")


def validate_install_cli_args(args: Namespace) -> None:
    if args.alias:
        validate_alias(args.alias)

    if args.ethpm_dir:
        validate_ethpm_dir(args.ethpm_dir)

    if args.uri:
        validate_target_uri(args.uri)
    elif args.etherscan:
        validate_address(args.etherscan)
        if "package_name" not in args:
            raise InstallError(
                "To install an Etherscan verified contract, you must specify a --package-name."
            )

        if "version" not in args:
            raise InstallError(
                "To install an Etherscan verified contract, you must specify a --version."
            )
    else:
        raise UriNotSupportedError(
            "--uri or --etherscan arg must be provided to install a package."
        )


def validate_uninstall_cli_args(args: Namespace) -> None:
    validate_package_name(args.package)
    if args.ethpm_dir:
        validate_ethpm_dir(args.ethpm_dir)


def validate_verify_cli_args(args: Namespace, config: Config) -> None:
    validate_address(args.address)
    validate_package_is_installed(args.contract_type, config)


def validate_package_is_installed(contract_type_id: str, config: Config) -> None:
    package, contract_type = contract_type_id.split(":")
    validate_package_name(package)
    if not is_package_installed(package, config):
        raise InstallError(f"{package} is not installed.")


def validate_address(address: Address) -> None:
    if not is_hex_address(address):
        raise ValidationError(f"{address} is not a valid hex address.")


def validate_etherscan_key_available() -> None:
    if ETHERSCAN_KEY_ENV_VAR not in os.environ:
        raise EtherscanKeyNotFound(
            "No Etherscan API key found. Please ensure that the "
            f"{ETHERSCAN_KEY_ENV_VAR} environment variable is set."
        )


def validate_target_uri(uri: URI) -> None:
    if (
        not is_ipfs_uri(uri)
        and not is_valid_registry_uri(uri)  # noqa: W503
        and not is_valid_content_addressed_github_uri(uri)  # noqa: W503
    ):
        raise UriNotSupportedError(
            f"Target uri: {uri} not a currently supported uri. "
            "Target uris must be one of: ipfs, github blob, or registry."
        )


def validate_alias(alias: str) -> None:
    try:
        validate_package_name(alias)
    except EthPMValidationError:
        raise ValidationError(
            f"{alias} is not a valid package name. All aliases must conform "
            "to the ethpm spec definition of a package name."
        )


def validate_ethpm_dir(ethpm_dir: Path) -> None:
    if ethpm_dir.name != "_ethpm_packages" or not ethpm_dir.is_dir():
        raise InstallError(
            f"--ethpm-dir must point to an existing '_ethpm_packages' directory."
        )


def validate_chain_data_store(chain_data_path: Path, w3: Web3) -> None:
    """
    Validates that chain_data_path points to a file corresponding
    to the provided web3 instance.
    """
    if not chain_data_path.is_file():
        raise InstallError(
            f"{chain_data_path} does not appear to be a valid EthPM CLI datastore."
        )

    chain_data = json.loads(chain_data_path.read_text())
    if chain_data["chain_id"] != w3.eth.chainId:
        raise InstallError(
            f"Chain ID found in EthPM CLI datastore: {chain_data['chain_id']} "
            f"does not match chain ID of provided web3 instance: {w3.eth.chainId}"
        )
