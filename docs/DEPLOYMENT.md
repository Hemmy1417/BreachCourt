# Deployment

The workflow, then only facts a receipt, a read or a command output shows. Every
recorded value is in `deploy/deployment.json`, written by
`scripts/deploy_studionet.py`.

## Assumptions

| Item | Value |
|---|---|
| Network | GenLayer StudioNet, chain id 61999, RPC `https://studio.genlayer.com/api`, explorer `https://explorer-studio.genlayer.com` |
| Gas | StudioNet is gasless, and no method of this contract is payable |
| Wallets | the deployer key is created on first use in `.data/deployer.json`; the demo wallets' keys are in `.data/demo_wallets.json` (`scripts/make_wallets.py`); `.data/` is gitignored and no key is ever printed |
| Environment variables | none required. `GENVM_VERSION=v0.3.0-rc7` pins the linter and the test runner when other GenVM bundles are cached; `BREACHCOURT_LIVE_WRITES=1` opts the integration suite into one write |
| Runner | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` |
| Evidence | a live run serves `fixtures/evidence/` from two commit-pinned origins - `raw.githubusercontent.com` and the jsDelivr mirror of the same commit - which return identical bytes. A challenge that asks for two independent origins cannot be satisfied from one host |
| Target | VaultLite is a fixture that exists only in this repository's documents. Nothing in this repository attacks any real protocol |

## Workflow

```bash
pip install -r requirements-test.txt
```

```bash
python scripts/fetch_genvm_bundle.py
```

```bash
genvm-lint check contracts/breachcourt.py --json
```

```bash
python scripts/generate_fixtures.py --check
```

```bash
python -m pytest tests/direct -q
```

```bash
python scripts/mutation_check.py
```

Deploy and capture the address - the script refuses an uncommitted, non-ASCII or
CR-bearing contract, waits for FINALIZED, requires leader execution SUCCESS, reads
the deployed source back with `gen_getContractCode` and writes
`deploy/deployment.json` only after the byte comparison:

```bash
python scripts/deploy_studionet.py
```

```bash
python scripts/deploy_studionet.py --verify
```

```bash
python -m pytest tests/integration -q
```

The live run walks the catalogue with real transactions, in phases, and can be
resumed:

```bash
python scripts/live_run.py <address> --raw-base https://raw.githubusercontent.com/<owner>/<repo>/<commit>/fixtures/ --phase full
```

By hand, with any GenLayer client: `publish_challenge(challenge_json)` with a
template from `fixtures/challenges.json`; `get_definition_hash(challenge_id)`;
`submit_attempt(challenge_id, hash, summary, reference, claimed_impact,
evidence_json)`; `resolve(submission_id)`; `get_latest_resolution(submission_id)`;
after the window `finalize(submission_id)` and `is_exploit_confirmed`.

<!-- RECORD:START -->
## Canonical deployment

Filled by `scripts/deploy_studionet.py`.
<!-- RECORD:END -->

## Toolchain

| Tool | Version |
|---|---|
| Python | 3.12.2 |
| genlayer-py | 0.16.3 |
| genlayer-test (Direct Mode) | 0.29.2 |
| genvm-linter | 0.11.0, GenVM bundle v0.3.0-rc7 |

`GENVM_VERSION=v0.3.0-rc7` matters on a machine where another project has cached a
newer GenVM manager: the linter and the direct runner resolve the runner this
contract pins from that bundle, and a newer manager that no longer publishes it
fails with `E101 Failed to load SDK`. CI's cache is keyed to the same bundle.

<!-- DIAGNOSTIC:START -->
## The first live pass

Filled from `deploy/diagnostics/`.
<!-- DIAGNOSTIC:END -->

<!-- LIVERUN:START -->
## Live run of record

Filled from `deploy/live_run_transcript.json`.
<!-- LIVERUN:END -->
