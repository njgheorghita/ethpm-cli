import json

from ethpm.constants import INFURA_API_KEY

from ethpm_cli import CLI_ASSETS_DIR

ETHPM_DIR_NAME = "_ethpm_packages"
IPFS_ASSETS_DIR = "ipfs"
LOCKFILE_NAME = "ethpm.lock"
SRC_DIR_NAME = "_src"


VERSION_RELEASE_ABI = json.loads((CLI_ASSETS_DIR / "1.0.1.json").read_text())[
    "contract_types"
]["Log"]["abi"]
INFURA_HTTP_URI = f"https://mainnet.infura.io/v3/{INFURA_API_KEY}"
ETHERSCAN_KEY_ENV_VAR = "ETHPM_CLI_ETHERSCAN_API_KEY"
