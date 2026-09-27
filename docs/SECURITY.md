# Security

The threat model, what each boundary holds, and what this contract does not
defend against.

## Assets

| Asset | Why it is worth attacking |
|---|---|
| a **confirmed exploit verdict** | it is the signal monitoring, insurance and governance systems act on; a false confirmation is an attack on everything downstream |
| a **rejection** | it can be used to argue a protocol was tested and held; a false rejection buries a real exploit |
| the **challenge specification** | if it could change after an attempt was filed, the question could be rewritten around the answer |
| the **evidence record** | a dispute later reads the stored record; bytes nobody agreed on must never enter it |
| the **severity band** | it drives how urgently a downstream system reacts |

No funds. No method is payable, there is no treasury and no ledger, so there is
nothing to drain and no settlement to race.

## Actors

| Actor | Can | Cannot |
|---|---|---|
| challenge **publisher** (typically the protocol) | publish a challenge; cancel it *before* any attempt arrives; contest a verdict once inside its window | change a published challenge; cancel once an attempt exists; resolve, or influence a reading |
| **attacker / researcher** | file one attempt per challenge with up to four evidence items; withdraw it before resolution; contest a verdict once inside its window | file twice against one challenge, cite a source the challenge did not name, change the evidence after filing, or improve it for a second reading |
| **keeper** (anyone) | resolve, lapse, finalise | change any outcome - none of those calls carries a judgement |
| **validators** | reproduce the round and refuse the leader | write a verdict; they compare, code derives |
| **downstream consumer** | read verdicts and finality | write anything |

## Trust assumptions

- The hosts the challenge names are trusted only to *serve bytes*; nothing they
  say is trusted, and a `PINNED` item is trusted only to the extent it hashes to
  what was declared.
- Validators are assumed to retrieve independently. The corroboration floor and
  the digest binding are what remain when one validator is wrong.
- The model is assumed to be fallible and possibly adversarially prompted. It is
  never asked for a verdict, a reason or an amount, and every reading that bears
  on the outcome must quote the evidence.
- The publisher is assumed to be self-interested. This is why they cannot cancel a
  challenge that has attempts, cannot edit a specification, and cannot resolve.
- The attacker is assumed to be self-interested. This is why the challenge - not
  the submission - names the permitted sources, and why the attacker's own
  summary and claimed severity are labelled as claims in the panel's own input.

## Input attacks

**Prompt injection.** Every evidence document is data. `_markers` scans each
readable item in code for text addressed to whoever adjudicates - in the visible
text, in markup and attributes a reader never sees, and in the title - and undoes
the tricks that hide such text from a naive match: soft hyphens, zero-width
joiners, bidirectional controls, byte order marks, numeric character references,
and tags or comments splitting a word. A document carrying such text decides the
round in code as `SOURCE_ADDRESSES_ADJUDICATOR`; the panel is never convened. The
challenge's own fields are checked for the same markers at publication, and so are
the attacker's summary and reference, so no party can smuggle instructions through
a text field.

**A poisoned item is not dropped.** Judging the rest would let whoever poisoned it
choose which evidence counts, and with a corroboration floor, removing an item
changes what a confirmation can rest on.

**Evidence manipulation after filing.** A `PINNED` item's sha256 is declared by the
attacker at filing and verified against the bytes on every retrieval, in every
round. Serve different bytes later and the item is `DIGEST_MISMATCH` and the
verdict is `EVIDENCE_UNAVAILABLE` - never a confirmation, and never a fresh
reading of improved evidence.

**Unbound evidence.** A `LIVE` item has no digest, so a confirmation may not rest
on one. It can support a rejection, an inconclusive or an unavailable result.

**One publisher wearing several hats.** Corroboration is counted over distinct
hosts, not items, and a challenge cannot demand more origins than the sources it
named could provide.

**Fabricated support.** A quote is a quote only if it grounds in the text this node
retrieved, as a contiguous run of words; splices joined by an ellipsis are dropped
even though grounding would walk their parts. A quote attributed to an item it does
not appear in is re-attributed to the item it actually grounds in, or dropped. A
reading that bears on the verdict without a quote is downgraded to `UNCLEAR`, and
the downgrade is printed.

**Malformed or hostile model output.** Types are checked, not coerced; unknown
states, missing subjects, extra fields, booleans where integers belong and floats
where integers belong all fail closed.

**Replay.** One submission per account per challenge, enforced on
`challenge_id + attacker`. The same evidence may be filed against a *different*
challenge - a different specification is a different question about the same bytes
- and each submission carries its own commitment over its own item list.

**Stale specifications.** A submission commits to the challenge hash it read. The
hash of a different version, or of a different challenge, is refused at filing, and
every stored resolution records the hash its round judged under.

**Unauthorised mutation.** There is no method that edits a published challenge. Its
only writes are publishing and cancelling, and cancelling is impossible once an
attempt exists.

**Griefing by volume.** At most ten open submissions per account, at most four
evidence items each, at most 200 KB read per item and 9,000 normalised characters
shown to the panel. Every stored list is bounded; nothing grows without a cap.

## Fail-open / fail-closed policy

Fail-closed on the confirmation path, without exception: unreachable evidence, a
digest mismatch, an unusable panel answer, contradictory documents, an unclear
reading, too few origins, unbound bytes, or a severity nobody could read all
produce `INCONCLUSIVE` or `EVIDENCE_UNAVAILABLE`.

Fail-open is chosen deliberately in exactly one place: **rejections and
inconclusives need no corroboration floor**, because refusing to confirm an
exploit moves nothing and demanding corroboration to *withhold* a confirmation
would favour whoever benefits from silence.

Both sides of each asymmetry:

| Floor | Mirror |
|---|---|
| a confirmation needs the challenge's independent origins | a rejection needs none |
| a confirmation may not rest on `LIVE` bytes | a rejection may |
| a publisher cannot cancel a challenge with attempts | an attacker can always withdraw their own attempt before resolution |
| a contest is limited to one, inside a window | the window is wall-clock and anyone may finalise after it |
| evidence addressed to the adjudicator stops the round | so does the same text in the challenge or in the attacker's summary, refused at write time |

## Limitations

- **BreachCourt does not prove a protocol is secure.** A rejection means this
  evidence did not establish this challenge's conditions - nothing more.
- A confirmation means the submitted evidence satisfied conditions written in
  advance. It is not a claim about severity in the world, only about the band the
  challenge itself defined.
- Evidence availability changes. A verdict records what could be read at that
  moment, which is why the digest and the retrieval status are stored with it.
- Public-source verification is only as strong as the sources a challenge permits.
  A challenge that names a weak authority gets a weak verdict, and the permitted
  hosts are on the record for a reader to judge.
- The panel's readings are model judgements. Where honest models split, the round
  reaches no majority and stores nothing; that is the correct failure, not a
  defence.
- This is not a replacement for audits, formal verification, fuzzing, monitoring
  or professional review, and it is not an "AI auditor". It adjudicates bounded
  attempts against explicit specifications.
- Identity is a wallet. The per-account caps bound abuse; they do not prevent one
  person from using several wallets.
