#!/usr/bin/env python3
"""Mutation kill check: prove the Direct Mode suite pins each load-bearing
guard, not merely that the code passes today.

For each mutation the repository is copied to a scratch directory with ONE
guard in the contract mechanically broken, and the whole Direct Mode suite
runs against the copy. A mutation is KILLED when the suite fails and SURVIVED
when it passes (an unpinned guard). The run starts with an accept-control:
the unmodified copy must pass, or every kill would be vacuous.

Anchors are code TEXT, never line numbers. An anchor that is not found
exactly once is reported as ANCHOR MISSING - the guard moved or was deleted,
which is its own finding.

Run:  python scripts/mutation_check.py              (full sweep)
      python scripts/mutation_check.py --anchors    (anchor check only)
      python scripts/mutation_check.py --only gate  (names containing "gate";
                                                     separate several with |)
      python scripts/mutation_check.py --jobs 3     (three scratch copies)
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = "contracts/breachcourt.py"
Q = '"'


def off(condition: str) -> tuple:
    """(anchor, replacement) turning one `if` line into `if False:`."""
    head = condition[:len(condition) - len(condition.lstrip())]
    keyword = condition.lstrip().split(" ", 1)[0]
    return (condition + "\n", head + keyword + " False:\n")


def m(name: str, anchor: str, replacement: str = None) -> tuple:
    if replacement is None:
        anchor, replacement = off(anchor)
    return (name, anchor, replacement)


MUTATIONS = [
    # -- retrieval ------------------------------------------------------------------------
    m("a redirect is read as a retrieved item", "    if 300 <= code < 400:"),
    m("a 404 is a generic failure", "    if code in (404, 410):"),
    m("a forbidden document is a generic failure", "    if code in (401, 403):"),
    m("a server error is a generic failure", "    if code >= 500:"),
    m("a binary content type is read",
      '    if content_type != "" and not any(t in content_type for t in TEXT_TYPES):'),
    m("an undecodable body is read",
      '    if text is None:\n        return (_empty_source(INVALID_CONTENT',
      '    if False:\n        return (_empty_source(INVALID_CONTENT'),
    m("a document with no visible text is read", '    if normalized == "":'),
    m("scripts and styles count as text",
      "    if html:\n        text = _strip_markup(text)\n", ""),
    m("an oversized document is not marked partial",
      "    truncated = len(body) > BODY_BYTES_CAP or len(normalized) > TEXT_CAP\n",
      "    truncated = False\n"),
    # -- evidence integrity ---------------------------------------------------------------
    m("a pinned item's bytes are not checked against the declared digest",
      '        if item["kind"] == KIND_PINNED and source["status"] in READABLE \\\n'
      '                and source["raw_sha256"] != item["sha256"]:',
      "        if False:"),
    # Equivalent by construction: _markers returns nothing for an item whose status is
    # not readable, and a mismatched item's panel is skipped, so keeping its text in
    # the quotable set changes no reading. The two lines stay because they make the
    # intent explicit - a document that is not the one filed is not a source.
    m("a digest mismatch is judged by the panel anyway",
      '    if any(s["status"] == DIGEST_MISMATCH for s in sources):'),
    m("a round with no readable evidence is judged anyway",
      '    if not any(s["status"] in READABLE for s in sources):'),
    m("evidence addressing the adjudicator is judged anyway",
      "    if len(markers) > 0:\n        return \"SOURCE_ADDRESSES_ADJUDICATOR\"\n",
      "    if False:\n        return \"SOURCE_ADDRESSES_ADJUDICATOR\"\n"),
    m("text in the visible body is not scanned", "    if body_hit:"),
    m("markup and attributes are not scanned",
      "    if not body_hit and _evaluator_hits(_scan_form(raw_text)):"),
    m("the title is not scanned", '    if _evaluator_hits(_scan_form(source["title"])):'),
    m("nothing is bound to a declared item, so bytes are neither compared nor stored",
      "def _item_of(ctx: dict, evidence_id: str):\n"
      '    for item in ctx["evidence"]:\n',
      "def _item_of(ctx: dict, evidence_id: str):\n"
      "    return None\n"
      '    for item in ctx["evidence"]:\n'),
    # -- what a reading must show ----------------------------------------------------------
    m("a reading that bears on the verdict needs no quote",
      "    if state in QUOTED_STATES:\n        return len(quotes) > 0\n",
      "    if state in QUOTED_STATES:\n        return True\n"),
    m("a severity band needs no quote",
      "        return state in (IMPACT_NONE, UNCLEAR) or len(quotes) > 0\n",
      "        return True\n"),
    m("a spliced quote is accepted when the panel answers",
      '        if _spliced(rq["text"]):\n            continue\n', ""),
    m("a spliced quote passes the gate",
      '        if q in seen or _spliced(q["text"]) or not _quote_grounded(q, eligible, texts):',
      "        if q in seen or not _quote_grounded(q, eligible, texts):"),
    m("a quote need not ground in the text this node retrieved",
      "    return _grounds_in_order(_word_tokens(source), quote[\"text\"])\n",
      "    return True\n"),
    # Equivalent: dropping the eligibility check leaves texts.get(evidence_id) to
    # return None for an item the round did not read, refusing the quote the same way.
    # The check still earns its place on the second gate pass over the ratified
    # payload, where there are no texts to look in at all.
    # -- the verdict -----------------------------------------------------------------------
    m("a code reason is overridden by the panel's reading",
      '    reason = payload["panel_reason"]\n'
      '    if reason == "EVIDENCE_DIGEST_MISMATCH" or reason == "NO_EVIDENCE_READABLE":',
      '    reason = payload["panel_reason"]\n'
      "    if False:"),
    m("evidence addressing the adjudicator still reaches a verdict",
      '    if reason == "SOURCE_ADDRESSES_ADJUDICATOR":\n'
      '        return (INCONCLUSIVE, reason, "")',
      '    if False:\n        return (INCONCLUSIVE, reason, "")'),
    m("an unusable panel answer reaches a verdict",
      '    if payload["panel_state"] != PANEL_ASSESSED:\n'
      '        return (INCONCLUSIVE, "PANEL_UNUSABLE", "")',
      '    if False:\n        return (INCONCLUSIVE, "PANEL_UNUSABLE", "")'),
    m("contradictory evidence is confirmed anyway",
      "    if _state_of(payload, SUBJECT_CONSISTENCY) == CONTRADICTORY:"),
    m("an attack that was not shown is confirmed",
      "    if attack == NOT_SHOWN:"),
    m("an unclear attack is confirmed",
      '    if attack == UNCLEAR:\n        return (INCONCLUSIVE, "ATTACK_UNCLEAR", "")',
      '    if False:\n        return (INCONCLUSIVE, "ATTACK_UNCLEAR", "")'),
    m("evidence contradicting the claim is confirmed",
      "    if reached == CONTRADICTED:"),
    m("a prohibited state that was not reached is confirmed",
      "    if reached == NOT_SHOWN:"),
    m("an unclear prohibited state is confirmed",
      "    if reached == UNCLEAR:\n"
      '        return (INCONCLUSIVE, "PROHIBITED_STATE_UNCLEAR", "")',
      '    if False:\n        return (INCONCLUSIVE, "PROHIBITED_STATE_UNCLEAR", "")'),
    m("a required evidence requirement that was not met is confirmed",
      '        if requirement["required"] and state == NOT_MET:'),
    m("an unclear required requirement is confirmed",
      '        if requirement["required"] and state == UNCLEAR:'),
    m("an optional requirement blocks a confirmation",
      '        if requirement["required"] and state == NOT_MET:\n'
      '            return (EXPLOIT_REJECTED, "REQUIREMENT_NOT_MET", "")',
      "        if state == NOT_MET:\n"
      '            return (EXPLOIT_REJECTED, "REQUIREMENT_NOT_MET", "")'),
    m("the corroboration floor does not hold",
      '    if not pinned_only or len(origins) < ctx["challenge"]["min_independent_origins"]:',
      "    if not pinned_only:"),
    m("unbound bytes may carry a confirmation",
      '    if not pinned_only or len(origins) < ctx["challenge"]["min_independent_origins"]:',
      '    if len(origins) < ctx["challenge"]["min_independent_origins"]:'),
    m("corroboration counts items, not distinct hosts",
      '            hosts.append(_host_of(item["url"]))\n',
      '            hosts.append(item["evidence_id"])\n'),
    m("a severity nobody could read is confirmed",
      "    if impact in (UNCLEAR, IMPACT_NONE):"),
    # -- what validators compare -----------------------------------------------------------
    # What was retrieved is compared twice over: this function, and the statuses and
    # pinned digests inside the consequence. Either alone catches every difference the
    # other would, and no same-line mutation distinguishes them - a PINNED item cannot
    # differ between nodes without its digest differing, and a LIVE item's status is in
    # the consequence. Documented as an equivalent mutant rather than turned into a
    # false kill.
    m("the consequence is not compared",
      "    for key in sorted(mine.keys()):\n        if mine[key] != theirs[key]:\n",
      "    for key in sorted(mine.keys()):\n        if False:\n"),
    m("the leader's payload is gated against its own text, not this node's",
      "        parsed = _parse_payload(leader_res.calldata, ctx, own_texts)\n",
      "        parsed = _parse_payload(leader_res.calldata, ctx, None)\n"),
    m("a transient failure ratifies a different failure",
      "        if leader_text.startswith(ERROR_TRANSIENT):\n"
      "            return own_text.startswith(ERROR_TRANSIENT)\n"
      "        return own_text == leader_text\n",
      "        return True\n"),
    # -- the challenge ---------------------------------------------------------------------
    m("a challenge need not name its evidence sources",
      '    domains = spec["evidence_domains"]\n'
      "    if not isinstance(domains, list) or len(domains) < 1 or len(domains) > MAX_DOMAINS \\\n",
      '    domains = spec["evidence_domains"]\n'
      "    if False:\n"),
    m("a requirement id may shadow a built-in subject",
      "    if text.upper() in BUILT_IN_SUBJECTS:"),
    m("a severity band may be NONE or UNCLEAR",
      '        if entry["band"] in (IMPACT_NONE, UNCLEAR):'),
    m("no evidence requirement need be required",
      '    if not any(entry["required"] for entry in values):'),
    m("min_independent_origins may exceed the sources the challenge names",
      '    if spec["min_independent_origins"] > len(domains):'),
    m("challenge text may address the adjudicator",
      "    if _evaluator_hits(value) or _hidden_hits(value):"),
    m("a challenge may close in the past",
      "        if _iso_epoch(now) >= _iso_epoch(spec[\"submission_deadline\"]):"),
    m("the windows are unbounded",
      '        if not _int_in(spec[field], MIN_WINDOW, MAX_WINDOW):'),
    m("an IP literal is a host", "    if all_numeric or labels[-1].isdigit():"),
    # -- the evidence a submission declares ------------------------------------------------
    m("a pinned item needs no digest",
      '            if not _is_hex(entry["sha256"], 64):'),
    m("a live item may declare a digest it is not held to",
      '        elif entry["sha256"] != "":'),
    m("an item may come from any host at all",
      "        if not _domain_allowed(_host_of(canonical_url), domains):"),
    m("the same document may be declared twice",
      "        if canonical_url in urls:"),
    m("the evidence list is unbounded",
      "    if not isinstance(values, list) or len(values) < 1 or len(values) > MAX_EVIDENCE:"),
    m("the claimed impact need not be one of the challenge's bands",
      "        if claimed_impact not in _band_names(spec):"),
    m("the attacker's own text is not checked",
      "            error = _text_error(value, cap, label, newlines)\n"
      "            if error != \"\":\n                self._fail(error)\n"
      "        if claimed_impact not in _band_names(spec):",
      "        if claimed_impact not in _band_names(spec):"),
    # -- the state machine ------------------------------------------------------------------
    m("a submission may be resolved twice",
      '        if str(submission.status) != SUB_PENDING:\n'
      '            self._fail("only a PENDING submission is resolved")',
      '        if False:\n'
      '            self._fail("only a PENDING submission is resolved")'),
    m("a submission may be resolved after its window",
      '        if _iso_epoch(now) > _iso_epoch(str(submission.window_ends)):\n'
      '            self._fail("the resolve window closed at " + str(submission.window_ends))',
      '        if False:\n'
      '            self._fail("the resolve window closed at " + str(submission.window_ends))'),
    m("a verdict may be contested twice", "        if bool(submission.contested):"),
    m("a stranger may contest a verdict",
      "        if self._sender_hex() not in (str(submission.attacker), "
      "str(challenge.publisher)):"),
    m("a verdict may be contested after its window",
      '        if _iso_epoch(now) > _iso_epoch(str(submission.window_ends)):\n'
      '            self._fail("the contest window closed at " + str(submission.window_ends))',
      '        if False:\n'
      '            self._fail("the contest window closed at " + str(submission.window_ends))'),
    m("a verdict may be made final inside its contest window",
      '        if _iso_epoch(now) <= _iso_epoch(str(submission.window_ends)):\n'
      '            self._fail("the contest window closes at " + str(submission.window_ends))',
      '        if False:\n'
      '            self._fail("the contest window closes at " + str(submission.window_ends))'),
    m("a submission may lapse while its window is open",
      '        if _iso_epoch(now) <= _iso_epoch(str(submission.window_ends)):\n'
      '            self._fail("the resolve window closes at " + str(submission.window_ends))',
      '        if False:\n'
      '            self._fail("the resolve window closes at " + str(submission.window_ends))'),
    m("anyone may withdraw somebody else's submission",
      "        if self._sender_hex() != str(submission.attacker):"),
    m("a challenge with submissions may be cancelled",
      "        if len(challenge.submission_ids) > 0:"),
    m("anyone may cancel a challenge",
      "        if self._sender_hex() != str(challenge.publisher):"),
    m("an attempt may be filed after the deadline",
      "        if status == CH_CLOSED:"),
    m("an attempt may be filed against a cancelled challenge",
      "        if status == CH_CANCELLED:"),
    m("the challenge hash a submission commits to is not checked",
      '        if challenge_hash != str(challenge.definition_hash):'),
    m("one account may file twice against one challenge",
      "        if held is not None:"),
    m("the open-submission cap does not hold",
      "        if self._counter_value(wallet) >= MAX_OPEN_PER_WALLET:"),
    m("a receipt stores a live item's bytes",
      '            pinned = item is not None and item["kind"] == KIND_PINNED\n',
      "            pinned = True\n"),
    m("every reading is marked compared",
      '            entry["compared"] = finding["id"] in compared\n',
      '            entry["compared"] = True\n'),
    m("the confirmed count is not corrected when a contest overturns",
      "        if was_confirmed and not now_confirmed:\n"
      "            self.confirmed_counter = u32(int(self.confirmed_counter) - 1)\n", ""),
]


def run_suite(workdir: pathlib.Path) -> bool:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/direct", "-q", "-x", "-p", "no:cacheprovider",
         "--no-header"], cwd=workdir, capture_output=True, text=True)
    return completed.returncode == 0


def check_anchors(source: str) -> int:
    missing = 0
    for name, old, _new in MUTATIONS:
        hits = source.count(old)
        if hits != 1:
            print(f"ANCHOR MISSING ({hits} hits): {name}")
            missing += 1
    return missing


def copy_repo(scratch: pathlib.Path, index: int) -> pathlib.Path:
    work = scratch / ("repo%d" % index)
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", "deploy", "artifacts", ".data", "docs"))
    return work


def main() -> None:
    source = (ROOT / CONTRACT).read_text(encoding="utf-8")
    missing = check_anchors(source)
    print(f"{len(MUTATIONS)} mutations, {missing} anchor problems")
    if "--anchors" in sys.argv:
        sys.exit(0 if missing == 0 else 1)
    only = ""
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].casefold()
    jobs = 1
    if "--jobs" in sys.argv:
        jobs = max(1, int(sys.argv[sys.argv.index("--jobs") + 1]))
    todo = [x for x in MUTATIONS if source.count(x[1]) == 1
            and (not only or any(part in x[0].casefold() for part in only.split("|")))]
    jobs = min(jobs, max(1, len(todo)))
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="evidence-receipt-mut-"))
    copies = [copy_repo(scratch, i) for i in range(jobs)]
    print("accept-control: unmodified copy must pass ...", flush=True)
    if not run_suite(copies[0]):
        print("CONTROL FAILED: the unmodified suite does not pass; aborting")
        shutil.rmtree(scratch, ignore_errors=True)
        sys.exit(1)
    print(f"control green; {len(todo)} mutations over {jobs} job(s)\n", flush=True)
    results = [None] * len(todo)
    cursor = [0]
    done = [0]
    lock = threading.Lock()

    def worker(work: pathlib.Path) -> None:
        target = work / CONTRACT
        while True:
            with lock:
                i = cursor[0]
                if i >= len(todo):
                    return
                cursor[0] = i + 1
            name, old, new = todo[i]
            target.write_text(source.replace(old, new), encoding="utf-8", newline="\n")
            passed = run_suite(work)
            target.write_text(source, encoding="utf-8", newline="\n")
            with lock:
                results[i] = passed
                done[0] += 1
                print(f"  [{done[0]}/{len(todo)}] {'SURVIVED' if passed else 'killed  '}: "
                      f"{name}", flush=True)

    threads = [threading.Thread(target=worker, args=(w,)) for w in copies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    shutil.rmtree(scratch, ignore_errors=True)
    print()
    killed = survived = 0
    for (name, _old, _new), passed in zip(todo, results):
        print(("SURVIVED: " if passed else "killed:   ") + name)
        survived += 1 if passed else 0
        killed += 0 if passed else 1
    print(f"\nmutations: {killed} killed, {survived} survived, {missing} anchor missing")
    sys.exit(0 if survived == 0 and missing == 0 else 1)


if __name__ == "__main__":
    main()
