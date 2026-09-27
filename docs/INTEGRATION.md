# Integration

How another Intelligent Contract - or a monitor, or an insurance system - reads a
BreachCourt verdict without reinterpreting storage.

## The consumer's interface

A consumer needs one view and, usually, one field:

```python
@gl.contract_interface
class IBreachCourt:
    class View:
        def is_exploit_confirmed(self, submission_id: str) -> dict: ...
        def get_verdict(self, submission_id: str) -> dict: ...
        def get_evidence_status(self, submission_id: str) -> dict: ...
        def get_definition_hash(self, challenge_id: str) -> dict: ...

    class Write:
        pass
```

Gating on a confirmed exploit, inside another contract:

```python
BREACHCOURT = Address("0x...")          # the canonical deployment

answer = IBreachCourt(BREACHCOURT).view().is_exploit_confirmed(submission_id)

if not answer["found"]:
    raise gl.vm.UserError("[EXPECTED] no such BreachCourt submission")
if not (answer["confirmed"] and answer["final"]):
    raise gl.vm.UserError("[EXPECTED] no final confirmed exploit for that submission")
# from here the consumer's own rules apply
```

The consumer needs **no** web access, **no** prompt, **no** equivalence principle
and **no** parsing of internal risk state. It reads a boolean and a finality flag.
That is the whole reuse surface.

## What each view answers

| Method | Returns |
|---|---|
| `is_exploit_confirmed(submission_id)` | `found`, `confirmed`, `final`, `verdict`, `impact` - the cheapest thing to poll |
| `get_verdict(submission_id)` | the machine-readable answer: `verdict`, `reason_code`, `impact`, `evidence_class`, `confirmed`, `final`, `resolved_at`, `resolution_id`, `rounds`, and the `challenge_hash` it was judged under |
| `get_evidence_status(submission_id)` | per item: its kind, status and whether it was compared; plus the evidence class, the independent origins a confirmation rested on, whether the bytes were bound, and any markers |
| `get_submission(submission_id)` | the attempt as filed, including `attack_summary` and `claimed_impact` - both flagged by `claims_are_untested` - and the evidence list with its commitment |
| `get_resolution(resolution_id)` / `get_latest_resolution` | one full record: every reading with its `compared` flag, every source record, the markers, the panel state, the excerpt |
| `get_history(submission_id)` | one line per round: mode, verdict, reason, impact, class |
| `get_challenge(challenge_id)` / `get_definition_hash` | the specification as published, its hash and version |
| `get_challenge_status(challenge_id, as_of)` | whether it still accepts attempts at that time |
| `get_actions(submission_id, as_of)` | what can happen next, and who may do it |
| `list_challenges` / `list_submissions` / `get_stats` / `get_config` | paging, counts, and the vocabulary every field above uses |

A view has no clock, which is why the two status views take `as_of`. Every write
checks its own transaction time.

## Reading a verdict correctly

Three rules a consumer should follow, in the contract's own vocabulary:

1. **`confirmed` is not `final`.** A confirmation inside its contest window can
   still be overturned by one contest. A monitor may act on `confirmed`; anything
   irreversible should wait for `final`.
2. **`INCONCLUSIVE` and `EVIDENCE_UNAVAILABLE` are not rejections.** They mean the
   evidence did not allow a determination, or could not be read. Treating them as
   "no exploit" is the mistake this vocabulary exists to prevent.
3. **The band is the challenge's own.** `impact` is one of the `severity_bands`
   that challenge published; compare it against `get_challenge`, not against a
   global scale.

## The three consumers, concretely

| Consumer | Call | Reaction |
|---|---|---|
| protocol security team | `get_latest_resolution` | read the findings, the origins and the excerpt behind the verdict; patch, then publish a new challenge against the patched version |
| monitoring system | `is_exploit_confirmed` | page on `confirmed`; escalate on `confirmed and final` |
| insurance / risk | `get_verdict` + `get_definition_hash` | open an incident with the band and the reason, recording which specification was in force |
| security governance | `get_verdict` with `final` true | use the receipt as the evidence for a bounded internal process |

## Writing, for the parties who do

| Method | Who |
|---|---|
| `publish_challenge(challenge_json)` | anyone; the sender becomes the publisher. Fields: [`../DECISION.md`](../DECISION.md#3-the-challenge) |
| `cancel_challenge(challenge_id)` | the publisher, only before the first attempt |
| `submit_attempt(challenge_id, challenge_hash, attack_summary, attack_reference, claimed_impact, evidence_json)` | the attacker; one per challenge |
| `withdraw_submission(submission_id)` | the attacker, while pending |
| `resolve(submission_id)` | anyone, inside the resolve window |
| `contest(submission_id)` | the attacker or the publisher, once, inside the contest window |
| `finalize(submission_id)` | anyone, after the contest window |
| `lapse_submission(submission_id)` | anyone, after the resolve window, if nobody resolved it |

`evidence_json` is a list of 1 to 4 items, each
`{"url", "kind", "sha256", "label"}` - `kind` is `PINNED` with the sha256 of the
exact bytes, or `LIVE` with an empty sha256 and no claim on a confirmation.

## Failures a client should expect

| Symptom | Meaning |
|---|---|
| leader execution `ERROR` with `[EXPECTED] ...` | the contract refused: a bad field, a closed window, a source outside the challenge's domains, a state that does not allow the call. The message says which |
| leader execution `ERROR` with `[TRANSIENT] ...` | the model call or the clock failed on that node; send it again |
| the transaction finalises but nothing changed | the round reached no majority. Nothing is stored; the submission is still pending |
| `EVIDENCE_UNAVAILABLE` with `EVIDENCE_DIGEST_MISMATCH` | the bytes served are not the bytes that were filed - a statement about the evidence, not about the exploit |
