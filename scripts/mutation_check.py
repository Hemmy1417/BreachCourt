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
    # -- retrieval -----------------------------------------------------------------------
    m("a redirect is read as a retrieved source", "    if 300 <= code < 400:"),
    m("a 404 is a generic failure", "    if code in (404, 410):"),
    m("a forbidden source is a generic failure", "    if code in (401, 403):"),
    m("a server error is a generic failure", "    if code >= 500:"),
    m("a binary content type is read",
      '    if content_type != "" and not any(t in content_type for t in TEXT_TYPES):'),
    m("an undecodable body is read",
      '    if text is None:\n        return (_empty_source(INVALID_CONTENT',
      '    if False:\n        return (_empty_source(INVALID_CONTENT'),
    m("a page with no visible text is read", '    if normalized == "":'),
    m("scripts and styles count as text",
      "    if html:\n        text = _strip_markup(text)\n", ""),
    m("an oversized source is not marked partial",
      "    truncated = len(body) > BODY_BYTES_CAP or len(normalized) > TEXT_CAP\n",
      "    truncated = False\n"),
    # -- what code decides before any panel ----------------------------------------------
    m("a round with no readable source is judged anyway",
      '    if not any(s["status"] in READABLE for s in sources):'),
    m("a source addressing the adjudicator is judged anyway", "    if len(markers) > 0:"),
    m("text in the visible body is not scanned", "    if body_hit:"),
    m("markup and attributes are not scanned",
      "    if not body_hit and _evaluator_hits(_scan_form(raw_text)):"),
    m("the title is not scanned",
      '    if _evaluator_hits(_scan_form(source["title"])):'),
    m("a poisoned source only blocks its own reading",
      '    if len(markers) > 0:\n        return "SOURCE_ADDRESSES_ADJUDICATOR"\n',
      '    if False:\n        return "SOURCE_ADDRESSES_ADJUDICATOR"\n'),
    # -- what a finding must show ---------------------------------------------------------
    m("a band met needs no quote",
      "    if state in QUOTED_STATES:\n        return len(quotes) > 0\n",
      "    if state in QUOTED_STATES:\n        return True\n"),
    m("a stated date need not appear in its quote",
      "            return len(quotes) > 0 and _date_in_quotes(date, quotes)\n",
      "            return len(quotes) > 0\n"),
    m("a date's month is not checked",
      "any(t in words for t in _month_tokens(month)) and any(",
      "True and any("),
    m("a date's day is not checked",
      "                t in words for t in _day_tokens(day)):\n",
      "                True for t in _day_tokens(day)):\n"),
    m("a finding that is not dated may carry a date",
      '    if date != "":\n        return False\n', ""),
    m("a spliced quote is accepted when the panel answers",
      '        if _spliced(rq["text"]):\n            continue\n', ""),
    m("a spliced quote passes the gate",
      '        if q in seen or _spliced(q["text"]) or not _quote_grounded(q, eligible, texts):',
      "        if q in seen or not _quote_grounded(q, eligible, texts):"),
    m("a quote need not ground in the text this node retrieved",
      "    return _grounds_in_order(_word_tokens(source), quote[\"text\"])\n",
      "    return True\n"),
    # Dropping the eligibility check leaves `texts.get(evidence_id)` to return
    # None for a source the round did not read, which refuses the quote the same
    # way - an equivalent mutant. The check still earns its place: on the second
    # gate pass over the ratified payload there are no texts to look in, and it
    # is the only thing standing between a stored receipt and a quote citing a
    # source nobody retrieved.
    # -- the band -------------------------------------------------------------------------
    m("the corroboration floor does not hold",
      '        if len(_cited_origins(ctx, payload, subject)) >= band["min_corroboration"]:',
      "        if True:"),
    # Superseded by counting origins: duplicates in the cited list of source ids
    # no longer change the count a band clears, so letting them through is
    # unobservable. "corroboration counts source labels, not distinct hosts"
    # above is the mutation that now carries this guard.
    m("the bands are read mildest first, so the mildest band wins",
      '    for index in range(len(charter["bands"]) - 1, -1, -1):',
      '    for index in range(len(charter["bands"])):'),
    m("a band that fell short is not recorded",
      '        if short == "":\n            short = band["band_id"]\n', ""),
    m("a code reason is overridden by the panel's reading",
      '    reason = payload["panel_reason"]\n    if reason != "":\n'
      '        return (NO_BAND, reason, "", [], UNDATED, "")\n',
      '    reason = payload["panel_reason"]\n    if False:\n'
      '        return (NO_BAND, reason, "", [], UNDATED, "")\n'),
    m("an unusable panel answer declares a band anyway",
      '    if payload["panel_state"] != PANEL_ASSESSED:\n'
      '        return (NO_BAND, "PANEL_UNUSABLE", "", [], UNDATED, "")',
      '    if False:\n'
      '        return (NO_BAND, "PANEL_UNUSABLE", "", [], UNDATED, "")'),
    m("the wrong hazard declares a band", "    if hazard == MISMATCH:"),
    m("an unclear hazard declares a band", "    if hazard == UNCLEAR:"),
    m("an undated onset declares a band",
      '    if outcome == UNDATED:\n        return (NO_BAND, "SIGNAL_UNDATED", "", [], UNDATED, onset)',
      '    if False:\n        return (NO_BAND, "SIGNAL_UNDATED", "", [], UNDATED, onset)'),
    m("an onset from months back is treated as this event",
      '    if _iso_epoch(ctx["now"]) - _iso_epoch(onset + "T00:00:00Z") > MAX_ONSET_LAG:'),
    m("a stale signal declares a band",
      '    if outcome == STALE:\n        return (NO_BAND, "SIGNAL_STALE", "", [], outcome, onset)',
      '    if False:\n        return (NO_BAND, "SIGNAL_STALE", "", [], outcome, onset)'),
    m("a date in the future vouches for freshness", "    if stated > now + 86400:"),
    m("the freshness window is ignored", "    if now - stated > max_age:"),
    m("freshness is aged even when the charter turned it off", "    if max_age == 0:"),
    # -- the relief decision ---------------------------------------------------------------
    m("a need outside the declared area qualifies", "    if area == OUTSIDE:"),
    m("an unclear area qualifies", "    if area == UNCLEAR:"),
    m("a contradicted need qualifies", "    if need == CONTRADICTED:"),
    m("an absent need qualifies", "    if need == ABSENT:"),
    m("an unclear need qualifies", "    if need == UNCLEAR:"),
    m("a need not linked to this event qualifies", "    if link == UNLINKED:"),
    m("an unclear link qualifies", "    if link == UNCLEAR:"),
    m("undated evidence qualifies",
      '    if outcome == UNDATED:\n        return (INCONCLUSIVE, "EVIDENCE_UNDATED", outcome, dated)',
      '    if False:\n        return (INCONCLUSIVE, "EVIDENCE_UNDATED", outcome, dated)'),
    m("evidence from before the onset qualifies",
      '    if ctx["onset"] != "" and dated < ctx["onset"]:'),
    m("stale evidence qualifies",
      '    if outcome == STALE:\n        return (INCONCLUSIVE, "EVIDENCE_STALE", outcome, dated)',
      '    if False:\n        return (INCONCLUSIVE, "EVIDENCE_STALE", outcome, dated)'),
    # -- what validators compare -----------------------------------------------------------
    # The panel state, the code reason and the markers are each a pure function
    # of the source records, and a digest is compared twice over - in what was
    # retrieved and in the consequence. Mutating one of them alone is caught by
    # another, so the sweep mutates the layer instead.
    m("what was retrieved is not compared at all",
      "def _evidence_difference(ctx: dict, own: dict, theirs: dict) -> str:\n",
      "def _evidence_difference(ctx: dict, own: dict, theirs: dict) -> str:\n"
      '    return ""\n'),
    m("the consequence is not compared",
      "    for key in sorted(mine.keys()):\n        if mine[key] != theirs[key]:\n"
      "            return key + \" mine=\" + repr(mine[key]) + \" theirs=\" + repr(theirs[key])\n",
      "    for key in sorted(mine.keys()):\n        if False:\n"
      "            return key + \" mine=\" + repr(mine[key]) + \" theirs=\" + repr(theirs[key])\n"),
    # A digest is compared twice over - in what was retrieved and in the
    # consequence - and stored in the receipt on the same condition, so the
    # sweep mutates the one thing all three rest on.
    m("every source is treated as DYNAMIC, so its bytes are compared nowhere",
      "def _stability_of(ctx: dict, source_id: str) -> str:\n"
      '    if ctx["kind"] != KIND_ASSESS:\n'
      '        return ctx["stability"]\n',
      "def _stability_of(ctx: dict, source_id: str) -> str:\n"
      "    if True:\n"
      '        return "DYNAMIC"\n'),
    m("the leader's payload is taken on trust",
      "        parsed = _parse_payload(leader_res.calldata, ctx, own_texts)\n",
      "        parsed = _parse_payload(leader_res.calldata, ctx, None)\n"),
    # Nothing in this contract raises a model failure - an unusable answer is a
    # panel state, not an error - so the guard that refuses to ratify one can
    # only ever see a leader from another version. It stays, and no test pins it.
    m("a transient failure ratifies a different failure",
      "        if leader_text.startswith(ERROR_TRANSIENT):\n"
      "            return own_text.startswith(ERROR_TRANSIENT)\n"
      "        return own_text == leader_text\n",
      "        return True\n"),
    # Direct Mode hands the leader's own payload back as the ratified one, and it
    # has already passed the gate, so the second pass cannot be pinned offline.
    # It guards the on-chain path, where the ratified text comes from consensus.
    # -- the charter -----------------------------------------------------------------------
    m("corroboration counts source labels, not distinct hosts",
      "        if len(_cited_origins(ctx, payload, subject)) >= band[\"min_corroboration\"]:",
      '        if len(cited) >= band["min_corroboration"]:'),
    m("a charter may demand more corroboration than it has hosts",
      '    err = _bands_error(charter["bands"], len(_origins(charter["monitors"])))\n',
      '    err = _bands_error(charter["bands"], len(charter["monitors"]))\n'),
    m("a request may cite any host at all",
      '        if not _domain_allowed(_host_of(url), spec["evidence_domains"]):'),
    m("the charter need not name its evidence authorities",
      '    evidence = charter["evidence_domains"]\n'
      "    if not isinstance(evidence, list) or len(evidence) < 1 or len(evidence) > MAX_DOMAINS \\\n",
      '    evidence = charter["evidence_domains"]\n'
      "    if False:\n"),
    m("a second look may judge different bytes",
      "    sources, texts, markers = _retrieve(ctx)\n    _same_evidence(ctx, sources)\n",
      "    sources, texts, markers = _retrieve(ctx)\n"),
    m("the bytes a decision rested on are never recorded",
      "        source = _source_of(payload, REQUEST_SOURCE_ID)\n"
      '        if source is not None and source["status"] in READABLE:\n'
      '            request.evidence_digest = source["content_digest"]\n', ""),
    m("evidence whose bytes were never agreed may be rechecked",
      '        if str(request.stability) == "DYNAMIC" and str(request.evidence_digest) == "":'),
    m("min_corroboration may exceed the watched sources",
      '        if not _int_in(entry["min_corroboration"], 1, monitors):'),
    m("a monitor may sit outside the charter's authority domains",
      "        if not _domain_allowed(_host_of(canonical_url), domains):"),
    m("the monitors need not be numbered in order",
      '        if entry["source_id"] != expected:'),
    m("a band id may shadow a built-in subject", "    if text.upper() in BUILT_IN_SUBJECTS:"),
    m("charter text may address the adjudicator",
      "    if _evaluator_hits(value) or _hidden_hits(value):"),
    m("a charter may promise more than one grant of its budget",
      '    if budget < _largest_grant(charter["bands"]):'),
    m("freshness may be turned off with any small number",
      "    if age != 0 and age < MIN_WINDOW:"),
    m("an amount may be sent as a number",
      "def _digits(value) -> bool:\n"
      '    return isinstance(value, str) and value != "" and all("0" <= ch <= "9" for ch in value)\n',
      "def _digits(value) -> bool:\n"
      "    return str(value) != \"\" and all(\"0\" <= ch <= \"9\" for ch in str(value))\n"),
    m("an IP literal is a host", "    if all_numeric or labels[-1].isdigit():"),
    # -- the state machine and the money ---------------------------------------------------
    m("an event may be assessed twice",
      '            if str(event.status) != EV_OPEN:',
      "            if False:"),
    m("an event may be reassessed twice",
      "            if bool(event.reassessed):"),
    m("an event may be assessed after its window",
      '            if at > _iso_epoch(str(event.window_ends)):\n'
      '                self._fail("the assessment window closed at "',
      '            if False:\n'
      '                self._fail("the assessment window closed at "'),
    m("an event may be finalized inside its window",
      '        if _iso_epoch(now) <= _iso_epoch(str(event.window_ends)):\n'
      '            self._fail("the reassessment window closes at "',
      '        if False:\n'
      '            self._fail("the reassessment window closes at "'),
    m("a request may be filed against an event with no declaration",
      '        if band_id in ("", NO_BAND):'),
    m("a request may ask for a category the band does not promise",
      "        if _relief_for(band, category) is None:"),
    m("a second request may cite a source another request holds",
      "        if held is not None:"),
    m("a request may be adjudicated after its window",
      '        if _iso_epoch(now) > _iso_epoch(str(request.window_ends)):\n'
      '            self._fail("the adjudication window closed at "',
      '        if False:\n'
      '            self._fail("the adjudication window closed at "'),
    m("a request may be rechecked twice", "        if bool(request.rechecked):"),
    m("a request may be settled inside its recheck window",
      '        if _iso_epoch(now) <= _iso_epoch(str(request.window_ends)):\n'
      '            self._fail("the recheck window closes at "',
      '        if False:\n'
      '            self._fail("the recheck window closes at "'),
    m("a band withdrawn under a filed request is adjudicated anyway",
      "        if str(event.band_id) != str(request.band_id):"),
    m("the per-band grant cap does not hold",
      "        if self._counter_value(self.grants_used, self._grant_key(request)) \\\n"
      '                >= action["max_grants"]:',
      "        if False:"),
    m("the per-wallet grant cap does not hold",
      "        if self._counter_value(self.wallet_grants, self._wallet_key(request)) \\\n"
      '                >= spec["max_grants_per_wallet"]:',
      "        if False:"),
    m("a charter reserves more than its treasury holds",
      "        if amount > free:\n            return (0, \"TREASURY_SHORT\")\n",
      "        if False:\n            return (0, \"TREASURY_SHORT\")\n"),
    m("a superseded authorisation keeps its reservation",
      "        self._release(request, charter)\n", ""),
    m("a released reservation keeps its grant slot",
      "        self._bump(self.grants_used, self._grant_key(request), -1)\n"
      "        self._bump(self.wallet_grants, self._wallet_key(request), -1)\n", ""),
    m("settling pays a request that did not qualify",
      "        amount = int(request.reserved_atto)\n        if amount > 0:",
      "        amount = int(request.reserved_atto)\n        if True:"),
    m("a settled grant frees the source it rested on",
      "            self._credit(str(request.filer), amount)\n"
      "        else:\n            self._free_claim(request)\n",
      "            self._credit(str(request.filer), amount)\n"
      "        if True:\n            self._free_claim(request)\n"),
    m("a lapsed request keeps the source it cited",
      "        request.status = RQ_LAPSED\n        self._free_claim(request)\n",
      "        request.status = RQ_LAPSED\n"),
    m("withdrawing does not clear the ledger first",
      "        self.credits[wallet] = u256(0)\n"
      "        self.credits_total_atto = u256(int(self.credits_total_atto) - amount)\n", ""),
    m("anyone may fund a charter",
      '            reason = "only the charter\'s steward funds its treasury"',
      '            reason = ""'),
    m("a refused deposit is raised away instead of returned",
      '            if value > 0:\n                return self._return_deposit("fund_charter", reason)\n',
      "            if False:\n                pass\n"),
    m("anyone may reclaim a charter's treasury",
      '        if self._sender_hex() != str(charter.steward):\n'
      '            self._fail("only the charter\'s steward reclaims its treasury")',
      '        if False:\n'
      '            self._fail("only the charter\'s steward reclaims its treasury")'),
    m("a reserved grant may be reclaimed",
      '        if str(charter.status) != CHARTER_RETIRED:\n'
      '            self._fail("retire the charter first")\n'
      "        free = int(charter.pool_atto) - int(charter.reserved_atto)\n",
      '        if str(charter.status) != CHARTER_RETIRED:\n'
      '            self._fail("retire the charter first")\n'
      "        free = int(charter.pool_atto)\n"),
    m("a retired charter still takes funds",
      '            reason = "a retired charter takes no funds"', '            reason = ""'),
    m("an event may be opened against a retired charter",
      "        if str(charter.status) != CHARTER_ACTIVE:\n"
      '            self._fail("the charter is retired")',
      "        if False:\n"
      '            self._fail("the charter is retired")'),
    m("the charter hash an event commits to is not checked",
      '        if charter_hash != str(charter.definition_hash):\n'
      '            self._fail("charter_hash does not match the charter")\n'
      "        for value, cap, label in ((situation, SITUATION_CAP, \"situation\"),",
      "        if False:\n"
      '            self._fail("charter_hash does not match the charter")\n'
      "        for value, cap, label in ((situation, SITUATION_CAP, \"situation\"),"),
    m("the open-event limit does not hold",
      '        if self._counter_value(self.open_counts, "E:" + wallet) >= MAX_OPEN_PER_WALLET:'),
    m("the open-request limit does not hold",
      '        if self._counter_value(self.open_counts, "R:" + wallet) >= MAX_OPEN_PER_WALLET:'),
    m("a receipt stores a dynamic source's digest",
      '            stable = _stability_of(ctx, source["source_id"]) == "STABLE"\n',
      "            stable = True\n"),
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
