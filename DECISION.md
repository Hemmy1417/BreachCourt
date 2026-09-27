# Decisions

The specification, written before the contract, and the reasoning behind each
choice. What the brief fixed is marked as fixed; everything else is a decision
this document owns.

## 1. The exact trust question

> **Given a challenge's declared security invariant and success conditions, and
> the evidence that challenge permits, did this submitted attack actually produce
> the prohibited outcome?**

Not "is this protocol vulnerable", not "does this code look unsafe". One bounded
attempt, against one invariant that was written down before the attempt existed,
judged on evidence whose bytes every validator retrieves and verifies for itself.

**Delete GenLayer and what breaks:** the protocol's own security team, or one
backend, becomes the authority on whether the exploit that targets them
succeeded. The party with the most to lose from a confirmation decides the
confirmation. A scanner cannot replace it either: the question is not about the
code's shape, it is about whether *this* execution evidence satisfies *this*
written success condition - a reading of prose against traces, receipts and
state, which is exactly the judgement several independent validators can make and
compare.

## 2. What each side owns

| Deterministic code | GenLayer consensus |
|---|---|
| the challenge, its hash, and the specification version a submission commits to | whether the evidence shows the attack actually ran against the target |
| every field limit, URL admission, the permitted evidence sources | whether it shows the prohibited state was reached |
| evidence integrity: a declared sha256 verified against the bytes fetched | whether the evidence contradicts the claim |
| which evidence is reachable, unavailable, mismatched, or addressed to the adjudicator | whether each of the challenge's evidence requirements is met |
| how many independent origins a confirmation rests on | which of the challenge's declared severity bands the evidence supports |
| the verdict, its reason, and the evidence class | whether the items are consistent with each other |
| deadlines, windows, one submission per attacker per challenge, replay, caps | |
| every state transition, and what a consumer reads | |

The model never returns a verdict, a reason code or a final severity. It returns
readings; code turns readings into a verdict.

## 3. The challenge

Immutable once published, hashed, and versioned. A submission commits to the
hash, so a challenge cannot be reinterpreted under a submission that was filed
against it.

| Field | Rule |
|---|---|
| `name`, `target_name` | 1-80 characters, one line |
| `target_identifier` | 1-100: an address, a pool name, a deployment id - whatever identifies the thing attacked |
| `network_id` | 1-40: the chain or environment the target lives on |
| `security_property` | 1-400: the invariant, in words |
| `success_condition` | 1-400: what counts as a successful exploit |
| `evidence_requirements` | 1-4 of `{requirement_id, description, required}`: what the evidence must show |
| `evidence_domains` | 1-4 lowercase host suffixes: the sources this challenge will read |
| `min_independent_origins` | 1-3: how many distinct hosts a confirmation must rest on |
| `severity_bands` | 1-4 of `{band, description}`, mildest first: the severity vocabulary this challenge uses |
| `submission_deadline` | ISO: after it, no new submissions |
| `resolve_window`, `contest_window` | 60 to 2,592,000 seconds each |
| `spec_version` | a positive integer the publisher controls |

**Why `evidence_domains` is in the challenge and not in the submission.** The
party being judged is the protocol, and the party supplying the evidence is its
adversary; neither should choose the sources after the fact. The challenge names
them while nothing has happened yet, which is the only moment at which the choice
is disinterested.

**Why `min_independent_origins` counts hosts, not items.** Four screenshots from
one site are one publisher. Corroboration is counted over distinct hosts, and a
challenge cannot demand more than its own `evidence_domains` could provide.

## 4. The submission

One per attacker per challenge. Its evidence and its claims are bound at filing.

| Field | Rule |
|---|---|
| `challenge_id`, `definition_hash` | the specification the attacker read |
| `attacker` | the signer; no method takes an account as data |
| `attack_summary` | 1-600: **the attacker's own account of what they did - a claim to test, never a fact** |
| `attack_reference` | 1-200: the transaction hash, trace id or run identifier, as declared |
| `claimed_impact` | one of the challenge's severity bands - **also a claim**, and never the impact that is recorded |
| `evidence` | 1-4 items of `{evidence_id, url, kind, sha256, label}` |

**Evidence kinds, and the rule that follows from them.**

- `PINNED`: the attacker declares the sha256 of the exact bytes. Every node
  verifies the fetch against it. The bytes a later round reads are therefore the
  bytes the first round read, or the item is a mismatch and the verdict fails
  closed - there is no way to improve the evidence after a reading.
- `LIVE`: no digest. Useful for an explorer page that changes, but its content is
  not bound, so **a confirmation may never rest on it**. A LIVE item can support
  a rejection, an inconclusive or an unavailable result, and can never carry a
  positive verdict on its own.

That asymmetry is deliberate: the dangerous direction is a false confirmation,
because a confirmation is the signal downstream systems act on.

## 5. The state machine

```
challenge:  OPEN ──(deadline passes)──> CLOSED
              └──(publisher, before any submission)──> CANCELLED

submission: PENDING ──resolve──> RESOLVED{verdict} ──finalize──> FINAL
              │                      └──contest (once, in window)──> RESOLVED{verdict}
              ├──withdraw (attacker, before resolution)──> CANCELLED
              └──lapse (nobody resolved it in the window)──> CANCELLED
```

Verdicts: `EXPLOIT_CONFIRMED`, `EXPLOIT_REJECTED`, `INCONCLUSIVE`,
`EVIDENCE_UNAVAILABLE`, `CANCELLED`.

**A publisher cannot cancel a challenge that already has submissions.** The
obvious abuse of a cancel power is burying a pending exploit; a publisher may
stop new submissions before any arrive, and after that only the deadline closes
the challenge. An attacker may withdraw their own submission before it is
resolved, and nobody else may.

**Every hold has an exit.** `resolve` is permissionless; a submission nobody
resolved inside its window can be lapsed by anyone; `finalize` is
permissionless. No state waits on an actor who may never act.

## 6. What the panel is asked, and what code does with it

One consensus round per resolution. The panel answers only readings:

| Subject | States |
|---|---|
| `ATTACK_EXECUTED` | `SHOWN`, `NOT_SHOWN`, `UNCLEAR` |
| `PROHIBITED_STATE` | `SHOWN`, `NOT_SHOWN`, `CONTRADICTED`, `UNCLEAR` |
| `EVIDENCE_CONSISTENCY` | `CONSISTENT`, `CONTRADICTORY`, `UNCLEAR` |
| `IMPACT` | one of the challenge's bands, `NONE`, or `UNCLEAR` |
| one per evidence requirement | `MET`, `NOT_MET`, `UNCLEAR` |

Code derives the verdict in this order, and every ambiguous branch fails closed:

1. no evidence item readable -> `EVIDENCE_UNAVAILABLE`
2. a `PINNED` item whose bytes do not match its declared digest ->
   `EVIDENCE_UNAVAILABLE`, reason `EVIDENCE_DIGEST_MISMATCH`
3. any item addresses the adjudicator -> `INCONCLUSIVE`,
   reason `SOURCE_ADDRESSES_ADJUDICATOR` (the whole round, never by dropping the item)
4. the panel's answer is unusable -> `INCONCLUSIVE`, reason `PANEL_UNUSABLE`
5. `EVIDENCE_CONSISTENCY` contradictory -> `INCONCLUSIVE`, reason `EVIDENCE_CONTRADICTORY`
6. `ATTACK_EXECUTED` not shown -> `EXPLOIT_REJECTED`; unclear -> `INCONCLUSIVE`
7. `PROHIBITED_STATE` not shown -> `EXPLOIT_REJECTED`; contradicted ->
   `EXPLOIT_REJECTED`, reason `EVIDENCE_CONTRADICTS_CLAIM`; unclear -> `INCONCLUSIVE`
8. a required evidence requirement not met -> `EXPLOIT_REJECTED`; unclear -> `INCONCLUSIVE`
9. fewer independent origins behind the decisive readings than the challenge
   demands, or any decisive reading resting on `LIVE` evidence -> `INCONCLUSIVE`,
   reason `CORROBORATION_SHORT`
10. `IMPACT` unclear or outside the challenge's bands -> `INCONCLUSIVE`
11. otherwise `EXPLOIT_CONFIRMED`, at the band the panel read

`INCONCLUSIVE` and `EVIDENCE_UNAVAILABLE` are never collapsed into a
confirmation, and a failed fetch never becomes evidence of an exploit.

## 7. What validators compare

The consequence, not the prose: the verdict, the reason, the impact band where a
confirmation carries one, each evidence item's status and - for a `PINNED` item -
its digest, and where any item addresses the adjudicator. Notes, quote choice,
which requirement the panel happened to cite first, and the readings a reason did
not rest on are not compared: a reason already fixes the reading it names, so
comparing it again pins nothing while splitting rounds over readings that cannot
change the verdict.

## 8. Money

**None.** The brief's default, and the right one: a verdict here is a signal, and
the consumers that act on it - monitoring, insurance, governance - hold their own
funds and their own policies. Adding a bounty would import an economy this
primitive does not need and would give the publisher a reason to cancel. No
method is payable; there is no ledger and no treasury.

## 9. Scope, and what is deliberately absent

- **No frontend.** The brief fixes this: a standalone contract primitive.
- **No vulnerable fixture contract.** The demonstration uses committed evidence
  documents served from a pinned commit, so nothing in this repository attacks
  anything, and the catalogue does not become a museum of broken contracts.
- **No appeal ladder.** One contest, inside a window, on evidence whose bytes are
  bound by the attacker's own declared digests. That is a recovery path and a
  second reading, not an appeals court.
- **No universal auditor claim.** BreachCourt does not prove a protocol is
  secure, and a rejection is not a statement that no exploit exists. The README
  says so in its own section, not in a footnote.
- **No token, no scoring economy, no dashboard.**

## 10. The three consumers

One contract, four readers, no per-consumer variants:

| Consumer | What they read |
|---|---|
| a protocol security team | `get_submission`, `get_verdict`, `get_evidence_status` - the full record behind a decision |
| a monitoring system | `is_exploit_confirmed(submission_id)` - one boolean plus finality, cheap to poll |
| an insurance or risk system | `get_verdict` for the band and the reason, `get_definition_hash` to know which specification was in force |
| security governance | the same verdict, with `final` true, as the evidence for a bounded internal process |

A consumer never has to reinterpret storage: the views answer in the vocabulary
`get_config` publishes.
