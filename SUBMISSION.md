# Submission - BreachCourt

Copy-ready. No addresses, hashes or shell commands appear in the portal free-text
fields: the contract address goes only in the validated contract-link field, and
the repository goes in the evidence rows.

## Category

DeFi / smart-contract security / adversarial testing - a standalone GenLayer
Intelligent Contract primitive, no frontend.

## Title

BreachCourt - adversarial DeFi exploit adjudication

## One-line thesis

BreachCourt adjudicates whether bounded DeFi exploit attempts actually violated
predefined security invariants, using independently evaluated evidence and
deterministic state controls to produce machine-readable, consensus-backed
security verdicts.

<!-- IDENTITY:START -->
## Deployment

- **Repository:** https://github.com/Hemmy1417/BreachCourt
- **Canonical StudioNet address:** `0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D`
- **Explorer URL:** https://explorer-studio.genlayer.com/address/0xcE067Ba556d3b456331aF5ae939c0DF9460aed9D
- **Deployment tx:** `0xc439649cb81eb86c70fc973c8fe8c26d57513fa94faafab7421cf160b3c3d621`
- **Deployment source:** commit `e014836477b3e48d35c2f3d26f551fdc8726f1fc`, contract blob `9ec58fee8b380e675c22384240f46fd27b362a77`, deployed
  source byte-identical to the repository
<!-- IDENTITY:END -->

## Why GenLayer is required

A protocol under attack cannot be the judge of whether the attack worked. Delete
GenLayer and the protocol's own security team, or one backend, decides whether the
exploit against them succeeded - the party with the most to lose from a
confirmation decides the confirmation. A scanner does not fill the gap either: it
answers "does this code look vulnerable", where the question here is whether *this*
trace and *this* state satisfy *this* written success condition. That is a reading
of prose against execution evidence, which several independent validators can each
perform and compare.

## Consensus mechanism

One `run_nondet_unsafe` round per resolution. Every node retrieves each declared
evidence item, verifies a `PINNED` item's bytes against the sha256 the attacker
declared at filing, scans the documents in code for text addressed to whoever
adjudicates, and - only if code has not already decided - asks the panel for
readings: was the attack executed, was the prohibited state reached, do the items
agree, which declared severity band does the evidence support, is each evidence
requirement met. Every reading that bears on the verdict must quote the evidence,
and every validator re-grounds those quotes in the bytes it fetched itself.

Validators do not check the leader's JSON and stop: they reproduce the round from
their own retrieval and their own model call, then compare the verdict, the reason,
the severity band, each item's status and each pinned item's digest. Notes, quote
choice and readings the reason never reached may differ.

## Deterministic responsibilities

Identity (every recorded account is the signer); the challenge, its hash and the
version a submission commits to; every field limit; URL admission; the permitted
evidence sources; evidence integrity; which items are reachable, unavailable,
mismatched or addressed to the adjudicator; how many independent origins a
confirmation rests on; the verdict, its reason and the recorded severity; deadlines
and windows; one attempt per account per challenge; every state transition. The
model never returns a verdict, a reason code or a severity.

## Failure policy

Fail closed on the confirmation path, without exception: no readable evidence, a
digest that does not match what was filed, an item addressing the adjudicator, an
unusable model answer, contradictory documents, an unclear reading, too few
independent origins, evidence whose bytes were never bound, or a severity nobody
could read - each produces `INCONCLUSIVE` or `EVIDENCE_UNAVAILABLE`, never a
confirmation. A failed fetch never becomes evidence that an exploit succeeded.
Where validators disagree, the round stores nothing and the submission stays
pending until its window passes. Rejections need no corroboration floor, because
refusing to confirm moves nothing.

## Reuse surface

A consumer needs one view and one field:

```python
answer = IBreachCourt(BREACHCOURT).view().is_exploit_confirmed(submission_id)
if not (answer["confirmed"] and answer["final"]):
    raise gl.vm.UserError("[EXPECTED] no final confirmed exploit for that submission")
```

No web access, no prompts, no equivalence principle, no internal parsing. Four
readers of the same contract: protocol security teams reading the full record,
monitoring systems polling one boolean, insurance and risk systems taking the band
and the reason with the specification hash, and governance using a final verdict as
the evidence for a bounded internal process.

<!-- TESTS:START -->
## Test results

| Check | Result |
|---|---|
| Direct Mode | 136 passed (lifecycle, hardening, the attacker list, the fixtures) |
| pickling of nondeterministic closures | checked |
| GenVM lint + SDK validation | lint ok, validation ok, 23 methods (15 view, 8 write), exit 0 |
| mutation sweep | 75 mutations, 75 killed, 0 survived |
| fixtures | 15 files regenerate byte for byte |
| StudioNet integration | 6 passed, 1 skipped (the opt-in write) |
| source parity | the deployed blob is the blob at `main` |
<!-- TESTS:END -->

<!-- LIVE:START -->
## Live evidence

40 transactions against the canonical deployment, **24 of 26 outcomes held**, 10 of
10 refusals refused. All four verdicts were reached on chain: a confirmation at a
declared band resting on two independent origins with bound bytes; rejections for a
trace of another deployment and for an attempt that did not produce the prohibited
outcome; inconclusive results for contradictory documents, for a document
addressing the adjudicator, for evidence resting on one origin, and for evidence
whose bytes nobody bound; and unavailability for a document that is not published
and for a declared digest that could not match. Then a contest producing a second
reading of the same bytes, three finalisations, one lapse, and ten refusals.

The two outcomes that did not match the catalogue are the same model-variable line
- which rejection reason evidence of a failed attempt earns - and the verdict was
`EXPLOIT_REJECTED` every time. The transcript is left as the chain answered it, and
the variance is documented rather than re-run.

Two earlier passes against the same deployment are kept as diagnostic evidence;
the contract never changed, so no redeployment was needed.
<!-- LIVE:END -->

## Limitations

BreachCourt does not prove that a protocol is secure. A rejected submission does
not mean no other exploit exists. A confirmed exploit means the submitted evidence
satisfied the challenge's predefined conditions - nothing broader, and the severity
is the band that challenge itself defined. Evidence availability changes, so a
verdict records what could be read at that moment, with the digest and status
stored beside it. Public-source verification is only as strong as the sources a
challenge permits. The readings are model judgements, and where honest models split
the round stores nothing. This is not a replacement for formal verification,
audits, fuzzing, monitoring or professional security review, and it is not "AI
security that guarantees safety". Identity is a wallet; the per-account caps bound
abuse rather than preventing it. The demonstration target is a fixture that exists
only in this repository's documents.

## Reviewer fast path

1. `DECISION.md` - the specification written before the contract, the collision
   audit against the owner's own portfolio, and what was deliberately left out.
2. `docs/CONSENSUS.md` - the two nondeterministic calls, the structural gate, the
   decision-critical fields and the forged-leader defence table.
3. `contracts/breachcourt.py` - `_verdict_for` is the whole derivation in eleven
   ordered steps; `_retrieve` is the integrity check.
4. `docs/DEPLOYMENT.md` - the canonical deployment and a transaction table for the
   success, negative and lifecycle paths.
5. `tests/direct/test_breachcourt_adversarial.py` - forged verdicts, malformed
   JSON, unknown states, missing subjects, extra fields, boolean-as-integer,
   float-where-integer, invented references, missing references, fetch failure,
   contradictory sources, injection and its evasions, oversized evidence, replay,
   duplicate challenges, expired challenges, double resolution and stale
   specifications.

<!-- PORTAL:START -->
## Portal description (969 characters, limit 1000)

BreachCourt is a standalone GenLayer Intelligent Contract that adjudicates whether a bounded DeFi exploit attempt actually violated a security invariant the protocol declared in advance. A challenge fixes the target, the invariant, what counts as success, which sources may be read and how many independent origins a confirmation needs. Validators independently retrieve each evidence document, verify it against the sha256 the attacker declared at filing, and read it; deterministic code derives the verdict, the reason and the severity band, and fails closed on every ambiguity - an unreadable document, a digest that does not match, an injection, unbound bytes or too few origins can never become a confirmation. Consumers read one boolean plus finality. Verified with 136 Direct Mode tests, a 75-mutation sweep, GenVM lint and SDK validation, 6 live StudioNet integration tests, and a FINALIZED StudioNet deployment whose source is byte-identical to the repository.
<!-- PORTAL:END -->

## Evidence rows

| Type | What |
|---|---|
| repository | the GitHub repository (auto-badged) |
| contract link | the Studio explorer page for the canonical deployment |
