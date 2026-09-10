# Your registers

`vra connect` writes one YAML file per vendor here, and this directory is
gitignored: a real portfolio names your suppliers and your tenants, so it is
not something to commit to this repository.

The three demo vendors that ship with the project live in `sandbox/registers/`
and are loaded alongside whatever is here. A register in this directory
shadows a demo one with the same slug.

Point the tool at a different location with `VRA_VENDORS_DIR=/path/to/registers`.

Nothing in this directory is machine-owned. The tool records `last_assessed`
and snapshot hashes in `data/registry_state.json` and never rewrites a file
you authored.
