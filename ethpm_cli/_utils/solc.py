import json
from pathlib import Path

from eth_typing import Manifest
from eth_utils import to_tuple
from ethpm.tools import builder as b

from ethpm_cli import PROJECTS_DIR
from ethpm_cli.constants import SOLC_OUTPUT_FILENAME
from ethpm_cli.lo


BASE_SOLC_OUTPUT = {
    "language": "Solidity",
    "settings": {
	"outputSelection": {
	    "*": {
	        "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode", "metadata", "devdoc"]
	    }
	}
    }
}


#
#  solc --allow-paths base_dir --standard-json < solc_input.json > solc_output.json
#


def generate_solc_input(project: str):
    contracts_dir = PROJECTS_DIR / project / 'contracts'
    solc_output = BASE_SOLC_OUTPUT.copy()
    sources = contracts_dir.glob("**/*.sol")
    sources = {str(source.relative_to(contracts_dir)): {"urls": [str(source.resolve())]} for source in sources}
    solc_output['sources'] = sources
    (contracts_dir.parent / 'solc_input.json').touch()
    (contracts_dir.parent / 'solc_input.json').write_text(json.dumps(solc_output))
    print(f'solc_input written to {contracts_dir.parent}/{SOLC_OUTPUT_FILENAME}')


def get_manifest_from_solc_output(package_name: str, version: str, project_dir: Path) -> Manifest:
    solc_output = json.loads((project_dir / SOLC_OUTPUT_FILENAME).read_text())['contracts']
    sources = get_sources(solc_output)
    contract_types = get_contract_types(solc_output)
    built_sources = (b.inline_source(src, solc_output, (project_dir / 'contracts')) for src in sources)
    built_types = (b.contract_type(ctype, solc_output) for ctype in contract_types)
    return b.build(
        {},
        b.package_name(package_name),
        b.manifest_version("2"),
        b.version("1.0.0"),
        *built_sources,
        *built_types,
        b.validate(),
    )


@to_tuple
def get_contract_types(solc_output):
    for source in solc_output:
        for ctype in solc_output[source].keys():
            yield ctype


@to_tuple
def get_sources(solc_output):
    for source in solc_output:
        yield source.rstrip(".sol")
