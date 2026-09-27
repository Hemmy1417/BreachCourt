# Consensus

How one reading of the evidence becomes one typed verdict, and what validators may
and may not differ on.

## The exact nondeterministic calls

Two, and no others:

| Call | Where | What it does |
|---|---|---|
| `gl.nondet.web.get(url)` | `_fetch_source`, once per declared evidence item | retrieves the bytes, derives the source status from the HTTP answer and the content type, normalises the text a reader sees, takes the sha256 of the raw bytes and of the normalised text, extracts the title |
| `gl.nondet.exec_prompt(..., response_format="json")` | `_node_round`, once per round | asks the panel for readings, and only readings |

Both sit inside one `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` per
resolution. There is no other source of nondeterminism: no clock read, no random,
no float arithmetic on a decision path.

## What the leader does

`_node_round(ctx)`, on every node including the leader:

1. retrieves every item the submission declared (`_retrieve`);
2. verifies integrity: a `PINNED` item whose bytes do not hash to the sha256 the
   attacker declared at filing is recorded `DIGEST_MISMATCH` and becomes
   unreadable - neither the evidence that was filed nor something quotable;
3. scans in code for text addressed to the adjudicator (`_markers`): the visible
   text, the markup and attributes a reader never sees, the title;
4. derives the code reason (`_code_reason`) - a mismatch, no readable item, or an
   item addressing the adjudicator decides the round without the panel;
5. otherwise convenes the panel once and reduces each subject's answer to a
   finding (`_normalize_finding`), re-grounding every quote in this node's own
   text.

The leader returns that payload: one source record per declared item, the
markers, the code reason, the panel state, one finding per subject. **It contains
no verdict, no reason code and no severity** - those are code's, derived from the
findings.

## What the validator does

`_validator_decision` does not check the leader's JSON and stop. It:

1. **reproduces the round** from its own retrieval and its own model call;
2. runs the strict gate on the leader's payload **with its own texts**, so every
   quote must ground in the bytes this validator fetched;
3. compares what was retrieved (`_evidence_difference`);
4. derives its own verdict and compares the consequence
   (`_consequence_difference`);
5. prints the reason for every refusal, so a rotation is diagnosable.

A well-formed but substantively false leader result is refused at step 3 or 4.

## The structural gate

`_parse_payload` runs twice: on the leader's payload during validation, and again
on the ratified payload before anything is stored. It requires exact keys and
types; the same kind, mode, record, round, challenge hash, commitment and
transaction time; one source record per declared item in order, each internally
consistent (status against HTTP code, digests and title present only for a
readable item, truncation matching `PARTIAL`); a marker list that is sorted, free
of duplicates, names only readable items and real places, and never claims both
`BODY` and `META` for one item; the code reason recomputed from the source records
and markers; one finding per subject, in order, with clean notes, every quote
contiguous, within length, unique, grounded in this node's retrieval of the item
it cites; and every support rule met.

Types are checked, not coerced: a boolean where an integer belongs, a float where
an integer belongs, an extra field, a missing field, or a state outside the
subject's vocabulary each refuse the payload.

## Decision-critical fields

**What was retrieved** (`_evidence_difference`): the panel state, the code reason,
the marker list, and for every item its status, HTTP status and truncation - plus,
for a `PINNED` item, its byte count, normalised content digest, raw sha256, title
and content type.

**What it leads to** (`_consequence_difference`), derived by code:

| Field | Compared |
|---|---|
| `verdict` | every round |
| `reason_code` | every round |
| `impact` | wherever a confirmation carries a band |
| `statuses` (each item's) | every round |
| `digests` (each `PINNED` item's raw sha256) | every round |

## Equivalence: what may differ

Notes, which passage the panel chose to quote, the readings a reason never
reached, and everything about a `LIVE` item beyond its status. A `LIVE` item still
has to carry every quote the leader cites, in each validator's own retrieval.

The comparison carries values, not implications. A reason already fixes the
reading it names - `ATTACK_NOT_SHOWN` cannot coexist with the attack shown, and
`EXPLOIT_SHOWN` can only follow from the attack shown, the prohibited state shown,
every required item met and the corroboration floor cleared. Comparing those
states again would pin nothing; comparing the readings a refusal never reached
would split rounds over findings that cannot change the verdict.

## Forged-leader defence

| Forgery | What stops it |
|---|---|
| a verdict the readings do not support | the consequence comparison: each validator derives its own |
| a severity band nobody read | `impact` is compared, and a band needs a grounded quote |
| a quote that is not in the evidence | grounding, in each validator's own bytes |
| a quote citing an item the round did not read | the eligibility check, and the second gate pass where no texts exist |
| a spliced quote assembled from distant passages | `_spliced` refuses an ellipsis, even though grounding would walk its parts |
| a digest or status that was not what was fetched | the evidence comparison |
| a marker list hiding an injection, or inventing one | the reason is recomputed from the records |
| a payload about another submission, round or moment | the identity fields are compared against the round's own context |
| malformed JSON, extra fields, wrong types | the gate |

## Failure semantics

| Situation | Result |
|---|---|
| no item readable | `EVIDENCE_UNAVAILABLE` / `NO_EVIDENCE_READABLE` |
| a `PINNED` item's bytes are not the ones filed | `EVIDENCE_UNAVAILABLE` / `EVIDENCE_DIGEST_MISMATCH`, in code, no panel |
| an item addresses the adjudicator | `INCONCLUSIVE` / `SOURCE_ADDRESSES_ADJUDICATOR`, the whole round |
| the model's answer is unusable | `INCONCLUSIVE` / `PANEL_UNUSABLE` |
| the items contradict each other | `INCONCLUSIVE` / `EVIDENCE_CONTRADICTORY` |
| a reading is unclear | `INCONCLUSIVE`, with the subject in the reason |
| a confirmation would rest on one origin, or on unbound bytes | `INCONCLUSIVE` / `CORROBORATION_SHORT` |
| the model call fails on a node | `[TRANSIENT]`, ratified only by another transient failure |
| validators disagree | no majority, nothing stored, the submission stays `PENDING` until its window passes |

**A failed observation never becomes a world change.** Nothing in the derivation
turns an unreachable document, an unusable answer or an unclear reading into a
confirmed exploit - which is the only direction that matters, because a
confirmation is the signal downstream systems act on.

A leader that raised is ratified only by the same deterministic failure, or by a
transient failure meeting a transient one; a model failure (`[LLM_ERROR]`) is
never ratified, and a leader that failed where the validator succeeded is refused.

## Why consensus is load-bearing here

Delete it and the protocol's own security team - the party with the most to lose
from a confirmation - decides whether the exploit against them succeeded. A
scanner cannot take that place either: the question is not whether the code looks
unsafe, it is whether *this* trace and *this* state satisfy *this* written success
condition. That is a reading of prose against execution evidence, and it is
exactly what several independent validators can each do and compare.

What consensus is **not** asked for: the amounts (there are none), the caps, the
windows, the identity of anyone, the integrity of the bytes, or how many
independent origins a confirmation rests on. Code owns all of that.

<!-- LIVE:START -->
## Live findings

Three live passes ran against the canonical deployment; the first two are
diagnostic evidence under `deploy/diagnostics/`, the third is the run of record.
The contract was never changed in response to any of them - every fault was in the
catalogue that drives the run, or in the runner itself.

**What the panel proved it does.** Two independent origins, both hash-bound,
produced a confirmation at a declared band. A document addressing the adjudicator
stopped the round in code, with the marker recorded and the panel never convened. A
declared digest that could not match the served bytes produced
`EVIDENCE_UNAVAILABLE` with no panel at all. Two contradictory readings of one run
produced `INCONCLUSIVE`. The same two documents that confirm an exploit produced
`CORROBORATION_SHORT` when served from one host, and again when declared `LIVE`.

**Where independent panels differ, and it matters to read this precisely.**
Evidence of a *failed* attempt earns one of three rejection reasons, and the
reasons swapped between passes on the same documents:

| Case | Pass 2 | Run of record |
|---|---|---|
| a reverted `emergencyWithdraw` | `ATTACK_NOT_SHOWN` | `EVIDENCE_CONTRADICTS_CLAIM` |
| a call that paid out exactly the recorded claim | `EVIDENCE_CONTRADICTS_CLAIM` | `PROHIBITED_STATE_NOT_REACHED` |

The verdict was `EXPLOIT_REJECTED` in all four readings. The distinction between
"the evidence does not show the prohibited outcome" and "the evidence shows the
opposite" is a judgement about emphasis, not about whether the exploit succeeded,
and honest models place it differently. Two consequences were taken:

- the catalogue asserts the **verdict** strictly for those cases and accepts any of
  the three reasons, with the tolerance named in the generator rather than hidden;
- a consumer is told, in [`INTEGRATION.md`](INTEGRATION.md#reading-a-verdict-correctly),
  to act on the verdict and to treat the reason as diagnostic.

It would have been easy to re-run those two cases until a panel matched the
guess. That is chasing variance, and the transcript is left as the chain answered
it.
<!-- LIVE:END -->
