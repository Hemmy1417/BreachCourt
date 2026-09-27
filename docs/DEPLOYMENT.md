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

| Item | Value |
|---|---|
| Date | 2026-09-27T21:01:03Z |
| Network | GenLayer StudioNet |
| RPC | `https://studio.genlayer.com/api` |
| Chain ID | 61999 |
| Test SDK / client versions | genlayer-test 0.29.2, genlayer-py 0.16.3, genvm-linter 0.11.0 (bundle v0.3.0-rc7) |
| Python version | 3.12.2 |
| Deployment method | `scripts/deploy_studionet.py` over genlayer-py, `consensus_max_rotations=3` |
| Deployer public address | `0xa1e07F267e95D1d72968122e9c504F44D69964c0` |
| Deployment source commit | `e014836477b3e48d35c2f3d26f551fdc8726f1fc` |
| Contract blob SHA | `9ec58fee8b380e675c22384240f46fd27b362a77` |
| Contract source sha256 | `3920342f603a79a3d5834caf7631b6766d0f625d2e0c682f22bee46c63f6a6bc` |
| Canonical contract address | `0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D` |
| Explorer URL | https://explorer-studio.genlayer.com/address/0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D |
| Deployment tx | `0xc439649cb81eb86c70fc973c8fe8c26d57513fa94faafab7421cf160b3c3d621` |
| Lifecycle / finality | FINALIZED |
| Consensus result | leader execution SUCCESS, votes AGREE, AGREE, AGREE, AGREE, AGREE |
| Deployed source read back | `gen_getContractCode` sha256 `3920342f603a79a3d5834caf7631b6766d0f625d2e0c682f22bee46c63f6a6bc` - byte-identical |
| Schema | 23 methods (15 view, 8 write) |

`python scripts/deploy_studionet.py --verify` re-checks the pairing on demand.
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
## The two live passes before it

Both ran against this same deployment - the contract never changed, so no
redeployment was needed - and both are kept as evidence under
`deploy/diagnostics/`. Neither is the run of record.

| Pass | Record | What it found |
|---|---|---|
| 1 | `pass1_0xce067ba5.json`, `.log` | the mechanism works: a confirmation at HIGH from two independent origins with bound bytes, contradictory documents inconclusive, a missing document unavailable, a digest mismatch decided in code with no panel. Two faults, both in the catalogue: a case expecting `PROHIBITED_STATE_NOT_REACHED` from a reverted transaction, and two cases sharing one attacker wallet on one challenge (which the contract refuses by design) |
| 2 | `pass2_0xce067ba5.json`, `.log` | 13 of 16 held. Three more faults, none in the contract: the corroboration case declared a single document, so the panel answered `UNCLEAR` before the floor was reached; a case expecting `NOT_SHOWN` where the panel read `CONTRADICTED`; and the contest ran 17 minutes after the resolution it contests, past a 15-minute window |

The first sweep (`deploy/mutation_sweep_first.txt`) left seven survivors; five have
tests written for them and two are documented in `scripts/mutation_check.py` as
equivalent by construction.
<!-- DIAGNOSTIC:END -->

<!-- LIVERUN:START -->
## Live run of record

| Item | Value |
|---|---|
| Transcript | `deploy/live_run_transcript.json`, log `deploy/live_run.log` |
| Transactions | 40 in 40 steps |
| Window | 2026-09-27T22:22:17Z to 2026-09-27T23:01:45Z |
| Evidence served from | `raw.githubusercontent.com` and `cdn.jsdelivr.net`, both pinned to commit `d701344` and byte-identical |
| Outcomes held | **24 of 26** |
| Refusals | 10 of 10 refused |
| Contract state afterwards | {"challenges": 6, "confirmed": 3, "resolutions": 28, "submissions": 30} |

| Scenario | Action | Tx | Stored result |
|---|---|---|---|
| success | resolve EX01 - trace and state from two origins, bytes bound | `0xcdb2d7473a1c6a220b9588cb9b78f8c137b7d1058baf6e8219a7c3315fc679e4` | `EXPLOIT_CONFIRMED` / `EXPLOIT_SHOWN` / `HIGH`, origins `cdn.jsdelivr.net` and `raw.githubusercontent.com`, `bytes_bound` true |
| success, finalised | finalize EX01 | `0xaa8c94bbd078fa6774997bde57dd0248dee5d864375fd96331ac7250d7162d8e` | `final` true, `is_exploit_confirmed` -> confirmed and final |
| negative - contradictory | resolve EX03 | `0x30c740e68537bd6aa52921af42e6391503fbc367b9aa24fbef711f0b29c0c779` | `INCONCLUSIVE` / `EVIDENCE_CONTRADICTORY` |
| negative - unreadable | resolve EX04 | `0x6eb6db93a8eca52c50f5be593209278dcc7c076f22f0306944a482a1e6735486` | `EVIDENCE_UNAVAILABLE` / `NO_EVIDENCE_READABLE` |
| negative - integrity | resolve EX05, a declared digest that cannot match | `0x1d410b69ffe20bd14324421c07b44f9d4fd3f6cbda14a55e92534df576174504` | `EVIDENCE_UNAVAILABLE` / `EVIDENCE_DIGEST_MISMATCH`, decided in code, panel skipped |
| negative - injection | resolve EX06, a document addressing the adjudicator | `0x4ec72b9faabdab1ced0625108d72837c83689ffec67d11894c78af88c76a5b8b` | `INCONCLUSIVE` / `SOURCE_ADDRESSES_ADJUDICATOR`, markers recorded, panel skipped |
| negative - one origin | resolve EX07, the same two documents as EX01 from one host | `0xae5f6c367245f7dba6972607bc6041935831c7ed9207f8c22ad1e85fb237249a` | `INCONCLUSIVE` / `CORROBORATION_SHORT`, one origin |
| negative - unbound bytes | resolve EX08, both documents declared LIVE | `0xf11ba1570d23ed876216012d47eca5d88bef66eadf57072a342f89bb0a8d7e99` | `INCONCLUSIVE` / `CORROBORATION_SHORT`, `bytes_bound` false |
| negative - wrong target | resolve EX09, a trace of another deployment | `0xe7f5a4cf4775fc8a513082431ac03dd63c975496287ee79c9ebf57eecebc5f28` | `EXPLOIT_REJECTED` / `ATTACK_NOT_SHOWN` |
| negative - not the attack | resolve EX10 on a one-origin challenge | `0x21891271eb425b4c587af2c8b474087bbdc5c0ee03d3b825fe6db967d86d79cc` | `EXPLOIT_REJECTED` / `ATTACK_NOT_SHOWN` |
| lifecycle - contest | contest EX02, same bytes, second panel | `0x6f4620ddd71190b553e6d5375eacdf41bd771dd3e5038965fbdd0d6e291b990c` | round 2, superseding round 1, `EXPLOIT_REJECTED` |
| lifecycle - lapse | lapse an attempt nobody resolved | `0x55ee4d67aed3095cc6406bd104dff93bb596d88959cea05a7860ee7532d4d483` | `CANCELLED` / `LAPSED` |

Ten refusals, each refused: a mismatched challenge hash, an unknown challenge,
evidence from a host the challenge never named, a claimed impact outside its
bands, a second attempt from one account, cancelling a challenge that has
attempts, cancelling as somebody other than the publisher, resolving twice,
contesting as a stranger, and withdrawing somebody else's attempt.

### The two outcomes that did not match

| Case | Catalogue expected | Observed here | Observed in pass 2 |
|---|---|---|---|
| EX02 - the attempt reverted | `ATTACK_NOT_SHOWN` | `EVIDENCE_CONTRADICTS_CLAIM` | `ATTACK_NOT_SHOWN` |
| EX11 - the caller received exactly its recorded claim | `EVIDENCE_CONTRADICTS_CLAIM` | `PROHIBITED_STATE_NOT_REACHED` | `EVIDENCE_CONTRADICTS_CLAIM` |

Both are `EXPLOIT_REJECTED`, both times. Independent panels split on which
rejection reason evidence of a *failed* attempt earns - no attack shown, a
prohibited state not reached, or the claim contradicted - and the reasons swapped
between the two passes. The decision a consumer acts on did not move. The
catalogue now asserts the verdict strictly and accepts any of the three reasons for
those two cases (`FAILED_ATTEMPT_REASONS` in the generator), and this transcript is
left exactly as the chain answered rather than re-run for a tidier roll.

Integration against the deployment (`python -m pytest tests/integration -q`):
6 passed, 1 skipped.

**Source parity:** the deployment's blob `9ec58fee8b380e675c22384240f46fd27b362a77` is the blob at `main`. No
redeployment was needed at any point: every fault the passes found was in the
catalogue or the runner.
<!-- LIVERUN:END -->
