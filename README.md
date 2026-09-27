<p align="center">
  <img src="docs/assets/breachcourt-mark.svg" width="84" height="84" alt="BreachCourt">
</p>

<h1 align="center">BreachCourt</h1>

## Thesis

**BreachCourt is a reusable GenLayer Intelligent Contract that adjudicates whether
bounded DeFi exploit attempts actually violated predefined security invariants,
using independently evaluated evidence and deterministic state controls to produce
machine-readable, consensus-backed security verdicts.**

<!-- DEPLOYMENT:START -->
## Canonical deployment

[`0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D`](https://explorer-studio.genlayer.com/address/0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D) on GenLayer StudioNet (chain id 61999), from commit
`e014836`, deployed source read back with `gen_getContractCode` and
**byte-identical** to this repository. Deployment transaction
[`0xc439649cb81eb86c70fc973c8fe8c26d57513fa94faafab7421cf160b3c3d621`](https://explorer-studio.genlayer.com/tx/0xc439649cb81eb86c70fc973c8fe8c26d57513fa94faafab7421cf160b3c3d621), FINALIZED, leader execution SUCCESS, votes AGREE x5.
<!-- DEPLOYMENT:END -->

## The problem

A protocol under attack cannot be the judge of whether the attack worked.

Exploitability is not always reducible to a static check. Real questions look like
this: did the submitted transaction actually bypass the access restriction, or did
it merely trigger an expected revert? Did the oracle manipulation produce an
unauthorised state transition, or a price move inside the permitted band? Did the
reentrancy sequence produce an excess withdrawal, or exactly the caller's recorded
claim? Answering them means reading a trace, a state dump and a written
specification *together* - and today that reading is done by the protocol's own
security team, a bounty platform's triager, or one backend with one model behind
it.

BreachCourt turns that reading into a record: a challenge published before any
attempt exists, an attempt with evidence bound to its bytes, and a typed verdict
several independent validators had to agree on.

## Why GenLayer

The decision is semantic and adversarial at once. It needs:

- interpretation of execution evidence against a specification written in prose;
- independent retrieval, because the party supplying evidence is the protocol's
  adversary and the party judged is the protocol;
- a leader whose proposed verdict other validators can reject on substance, not on
  formatting;
- a record a third system can act on without trusting whoever produced it.

## Delete GenLayer: what breaks?

The protocol owner, a security operator, or one centralised backend becomes the
authority on whether the exploit against them succeeded - and the party with the
most to lose from a confirmation decides the confirmation. A scanner does not fill
the gap: it answers "does this code look vulnerable", where the question here is
"did *this* attempt, on *this* evidence, satisfy *these* predefined conditions".

## Why this is not a rejected pattern

It is not a generic AI auditor, and not an AI-as-backend wrapper:

| Rejected pattern | BreachCourt |
|---|---|
| "ask an LLM whether the contract is vulnerable" | asks whether specific evidence satisfies conditions the protocol wrote before the attempt |
| a model that produces the answer | the model returns readings only; code derives the verdict, the reason and the severity band |
| a database of vulnerability reports | a consensus-backed verdict with the evidence's integrity bound to it |
| an oracle for a number | an interpretation of prose against traces, where a single operator's word would otherwise be the record |

## Lifecycle

```
publish_challenge ─────────────────────── immutable, hashed, versioned
        │
        ├─ cancel_challenge (publisher, only before the first attempt)
        │
   submit_attempt ── resolve ──┬── contest (once, in window, attacker or publisher)
        │                      │
        │                      └── finalize (anyone, after the window) ── FINAL
        │
        ├─ withdraw_submission (attacker, before resolution)
        └─ lapse_submission (anyone, if nobody resolved it in time)
```

## Example challenge

```json
{
  "name": "VaultLite emergency withdrawal",
  "target_name": "VaultLite (fixture target)",
  "target_identifier": "0x5AFe0000000000000000000000000000000000Fe",
  "network_id": "testnet-fixture",
  "security_property": "Only an account holding the GUARDIAN role may call
    emergencyWithdraw, and no caller may receive more than its recorded claim.",
  "success_condition": "An account without the GUARDIAN role calls
    emergencyWithdraw and receives more than its recorded claim, and the vault's
    recorded balance falls accordingly.",
  "evidence_requirements": [
    {"requirement_id": "caller_role", "description": "...", "required": true},
    {"requirement_id": "value_moved", "description": "...", "required": true},
    {"requirement_id": "permitted_claim", "description": "...", "required": false}
  ],
  "evidence_domains": ["raw.githubusercontent.com", "cdn.jsdelivr.net"],
  "min_independent_origins": 2,
  "severity_bands": [
    {"band": "LOW", "description": "..."},
    {"band": "HIGH", "description": "..."},
    {"band": "CRITICAL", "description": "..."}
  ],
  "submission_deadline": "2026-10-05T12:00:00Z",
  "resolve_window": 1800,
  "contest_window": 900,
  "spec_version": 1
}
```

An attempt against it declares up to four evidence items, each from one of those
hosts, each either `PINNED` with the sha256 of its exact bytes or `LIVE` with none
- and a confirmation may never rest on a `LIVE` item.

## Contract surface

| Writes | |
|---|---|
| `publish_challenge`, `cancel_challenge` | the specification, and withdrawing it before anyone has attempted it |
| `submit_attempt`, `withdraw_submission` | one bounded attempt per account per challenge |
| `resolve`, `contest` | one consensus round each; contest at most once, by the attacker or the publisher |
| `finalize`, `lapse_submission` | permissionless exits, after the relevant window |

| Views | |
|---|---|
| `is_exploit_confirmed` | one boolean plus finality, for a monitor to poll |
| `get_verdict` | verdict, reason, impact, evidence class, finality, the specification hash |
| `get_evidence_status` | per item: kind, status, whether it was compared; plus origins and markers |
| `get_submission`, `get_resolution`, `get_latest_resolution`, `get_history` | the attempt and every round behind it |
| `get_challenge`, `get_definition_hash`, `get_challenge_status` | the specification as published |
| `get_actions`, `list_challenges`, `list_submissions`, `get_stats`, `get_config` | what may happen next, paging, counts, the vocabulary |

23 methods: 15 views, 8 writes, none payable.

## Nondeterministic operations

Exactly two, both inside one `run_nondet_unsafe` per resolution:
`gl.nondet.web.get` once per declared evidence item, and
`gl.nondet.exec_prompt(..., response_format="json")` once per round. The panel is
asked for readings - was the attack executed, was the prohibited state reached, do
the items agree, which declared band does the evidence support, is each evidence
requirement met - and for nothing else.

## Deterministic responsibilities

Identity (every recorded account is the signer); the challenge, its hash and the
version a submission commits to; every field limit; URL admission; the permitted
evidence sources; evidence integrity, by verifying a declared sha256 against the
bytes fetched; which items are reachable, unavailable, mismatched or addressed to
the adjudicator; how many independent origins a confirmation rests on; the verdict,
its reason and the recorded severity; deadlines and windows; one attempt per
account per challenge; and every state transition.

## Equivalence / validator design

Validators reproduce the round from their own retrieval and their own model call,
then compare the **consequence**: the verdict, the reason, the impact band where a
confirmation carries one, each item's status, and each `PINNED` item's digest. Not
compared: notes, which passage was quoted, and readings the reason never reached.
A leader payload that is well-formed but substantively false is refused, and the
refusal is printed. Details: [`docs/CONSENSUS.md`](docs/CONSENSUS.md).

## Safety and failure semantics

Every ambiguity fails closed on the confirmation path: no readable evidence, a
digest that does not match, an item addressing the adjudicator, an unusable model
answer, contradictory documents, an unclear reading, too few independent origins,
unbound bytes, or a severity nobody could read - each produces `INCONCLUSIVE` or
`EVIDENCE_UNAVAILABLE`, never a confirmation. A failed fetch never becomes evidence
that an exploit succeeded. Where validators disagree, the round stores nothing.

## Reuse surface

```python
answer = IBreachCourt(BREACHCOURT).view().is_exploit_confirmed(submission_id)
if not (answer["confirmed"] and answer["final"]):
    raise gl.vm.UserError("[EXPECTED] no final confirmed exploit for that submission")
```

No web access, no prompts, no equivalence principle, no internal parsing. Three
consumers read the same contract: security teams, monitoring systems, and
insurance or governance processes.
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Limitations

- **BreachCourt does not prove that a protocol is secure.**
- A rejected submission does not mean no other exploit exists.
- A confirmed exploit means the submitted evidence satisfied the challenge's
  predefined conditions - nothing broader.
- Evidence availability changes; a verdict records what could be read at that
  moment, with the digest and status stored beside it.
- Public-source verification is only as strong as the sources a challenge permits.
- The readings are model judgements; where honest models split, the round reaches no
  majority and stores nothing.
- This is not a replacement for formal verification, audits, fuzzing, monitoring or
  professional security review, and it is not "AI-powered security that guarantees
  safety".
- The demonstration target, VaultLite, is a fixture that exists only in this
  repository's documents. Nothing here attacks any real protocol.

## Verification

<!-- VERIFIED:START -->
| Check | Result |
|---|---|
| `python -m pytest tests/direct -q` | 136 passed |
| pickling of the nondeterministic closures | checked (`direct_vm.check_pickling = True`) |
| `genvm-lint check contracts/breachcourt.py --json` | lint ok (3 checks), validation ok, 23 methods (15 view, 8 write), exit 0 |
| `ruff check .` | clean |
| `python scripts/generate_fixtures.py --check` | 15 fixture files regenerate byte for byte |
| `python scripts/mutation_check.py` | 75 mutations, **75 killed, 0 survived** |
| `python scripts/deploy_studionet.py --verify` | deployed and repository sha256 equal, 23 schema methods |
| `python -m pytest tests/integration -q` | 6 passed, 1 skipped (the opt-in live write) |
| live run of record | 40 transactions, **24 of 26 outcomes held**, 10 of 10 refusals refused |

All four verdicts were reached by real transactions against the canonical
deployment, together with a contest, three finalisations, a lapse and ten
refusals. The two outcomes that did not match the catalogue are the same
model-variable line - which rejection reason evidence of a *failed* attempt earns -
and the verdict was `EXPLOIT_REJECTED` both times:
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md#live-run-of-record).
<!-- VERIFIED:END -->

## Reviewer fast path

1. [`DECISION.md`](DECISION.md) - the specification, the collision audit, and what
   was deliberately left out.
2. [`docs/CONSENSUS.md`](docs/CONSENSUS.md) - the two nondeterministic calls, the
   gate, and what validators compare.
3. `contracts/breachcourt.py` - `_verdict_for` is the whole derivation, in eleven
   ordered steps.
4. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) - the canonical deployment, and a
   transaction table for the success, negative and lifecycle paths.
5. `tests/direct/test_breachcourt_adversarial.py` - the attacker list, worked
   through one test at a time.

## Licence

MIT. See [`LICENSE`](LICENSE).
