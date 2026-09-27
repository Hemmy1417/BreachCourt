#!/usr/bin/env python3
"""Drive the deployed contract through the whole BreachCourt lifecycle with real
transactions, and record what the chain answered.

    python scripts/live_run.py <address> --raw-base <pinned raw url> --phase full

Phases run in order and can be run one at a time: challenges, cases, settle,
refusals. Every step is recorded in deploy/live_run_transcript.json under a
unique name; re-running skips steps already recorded, so a transport failure or a
rate limit never repeats work and never loses an id. A step whose write reverted
is retried on a resume, and no id is ever guessed for a write that did not
execute.

The evidence is served from two commit-pinned origins - raw.githubusercontent.com
and the jsDelivr mirror of the same commit - because a challenge that asks for two
independent origins cannot be satisfied from one host. Both return identical
bytes, which is what the declared digests are taken over.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import studionet_transport  # noqa: E402,F401 - retries RPC transport failures
from genlayer_py import create_account, create_client  # noqa: E402
from genlayer_py.chains import studionet  # noqa: E402
from genlayer_py.types import TransactionStatus  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
KEYS = ROOT / ".data" / "demo_wallets.json"
TRANSCRIPT = ROOT / "deploy" / "live_run_transcript.json"
LOG = ROOT / "deploy" / "live_run.log"
RPC = "https://studio.genlayer.com/api"
WAIT = dict(interval=5000, retries=300)
PHASES = ("challenges", "cases", "settle", "refusals")
DEADLINE_AFTER = 6 * 3600          # the deadline a run publishes its challenges with


def log(text: str):
    line = time.strftime("%H:%M:%S") + " " + text
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def now_iso(offset: int = 0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


# -- the transcript ------------------------------------------------------------

class Transcript:
    def __init__(self, address: str, raw_base: str, path=None):
        self.path = path or TRANSCRIPT
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.data = {"address": address, "raw_base": raw_base,
                         "started_at": now_iso(), "steps": {}, "order": []}
        if self.data["address"] != address:
            sys.exit("the transcript records a different contract; move it aside first")
        self.data["raw_base"] = raw_base

    def has(self, step: str) -> bool:
        return step in self.data["steps"]

    def get(self, step: str) -> dict:
        return self.data["steps"][step]

    def put(self, step: str, entry: dict):
        entry["at"] = now_iso()
        if step not in self.data["steps"]:
            self.data["order"].append(step)
        self.data["steps"][step] = entry
        self.save()

    def save(self):
        self.data["finished_at"] = now_iso()
        self.data["summary"] = self.summary()
        self.path.write_text(json.dumps(self.data, indent=1, sort_keys=True) + "\n",
                             encoding="utf-8")

    def summary(self) -> dict:
        steps = self.data["steps"].values()
        checks = [s for s in steps if "held" in s]
        return {
            "steps": len(self.data["order"]),
            "transactions": len([s for s in steps if s.get("tx")]),
            "outcomes_checked": len(checks),
            "outcomes_held": len([s for s in checks if s["held"]]),
            "missed": sorted(s["step"] for s in checks if not s["held"]),
            "refusals": len([s for s in steps if s.get("kind") == "refusal"]),
        }


# -- the chain -----------------------------------------------------------------

class Chain:
    def __init__(self, address: str, transcript: Transcript):
        self.address = address
        self.transcript = transcript
        keys = json.loads(KEYS.read_text(encoding="utf-8"))
        self.accounts = {name: create_account(account_private_key=key)
                         for name, key in keys.items()}
        self.clients = {name: create_client(chain=studionet, account=account,
                                            endpoint=RPC)
                        for name, account in self.accounts.items()}
        self.reader = self.clients[sorted(self.clients)[0]]

    def read(self, method: str, args=None):
        return self.reader.read_contract(address=self.address, function_name=method,
                                         args=args or [])

    def send(self, step: str, wallet: str, method: str, args=None, expect: dict = None,
             kind: str = "write") -> dict:
        if self.transcript.has(step):
            entry = self.transcript.get(step)
            if entry.get("leader_execution") == "SUCCESS":
                log("  skip " + step + " (recorded " + entry.get("status", "?") + ")")
                return entry
            log("  retry " + step + " (recorded " + str(entry.get("error"))[:80] + ")")
        client = self.clients[wallet]
        log("  " + step + ": " + method + " as " + wallet)
        tx = client.write_contract(address=self.address, function_name=method,
                                   args=args or [])
        receipt = client.wait_for_transaction_receipt(
            transaction_hash=tx, status=TransactionStatus.FINALIZED, **WAIT)
        entry = {"step": step, "kind": kind, "method": method, "wallet": wallet,
                 "args": _plain(args or []), "tx": _hex(tx), "status": _status(receipt),
                 "leader_execution": _execution(receipt), "votes": _votes(receipt),
                 "rounds": _rounds(receipt)}
        if entry["leader_execution"] != "SUCCESS":
            entry["error"] = _revert(receipt)
        if expect:
            entry.update(expect)
        self.transcript.put(step, entry)
        log("    " + entry["status"] + "/" + entry["leader_execution"] + " votes "
            + ",".join(entry["votes"]))
        return entry

    def created(self, entry: dict, step: str, method: str, args) -> dict:
        """Read back the id a successful write created. A write that reverted has
        created nothing, so the phase stops rather than guessing."""
        if entry.get("leader_execution") != "SUCCESS":
            raise SystemExit("  " + step + " did not execute: " + str(entry.get("error")))
        page = self.read(method, args)
        if not page["ids"]:
            raise SystemExit("  " + step + " executed but created nothing")
        return page

    def refuse(self, step: str, wallet: str, method: str, args=None,
               because: str = "") -> dict:
        """A write that must be refused. A refusal that depends on a window must be
        sent while that window is in the state the step is about."""
        if self.transcript.has(step):
            log("  skip " + step + " (recorded)")
            return self.transcript.get(step)
        client = self.clients[wallet]
        log("  " + step + ": expecting a refusal of " + method)
        entry = {"step": step, "kind": "refusal", "method": method, "wallet": wallet,
                 "args": _plain(args or []), "because": because}
        try:
            tx = client.write_contract(address=self.address, function_name=method,
                                       args=args or [])
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx, status=TransactionStatus.FINALIZED, **WAIT)
            entry["tx"] = _hex(tx)
            entry["status"] = _status(receipt)
            entry["leader_execution"] = _execution(receipt)
            entry["error"] = _revert(receipt)
            entry["held"] = entry["leader_execution"] != "SUCCESS"
        except Exception as err:                       # a client-side rejection counts
            entry["error"] = str(err)[:400]
            entry["held"] = True
        self.transcript.put(step, entry)
        log("    refused" if entry["held"] else "    NOT REFUSED - recorded as a miss")
        return entry


def _hex(value) -> str:
    return value if isinstance(value, str) else "0x" + bytes(value).hex()


def _plain(args) -> list:
    out = []
    for value in args:
        text = value if isinstance(value, (str, int, bool)) else str(value)
        if isinstance(text, str) and len(text) > 200:
            text = text[:200] + "... (" + str(len(text)) + " characters)"
        out.append(text)
    return out


def _status(receipt) -> str:
    for key in ("status", "statusName", "status_name"):
        value = receipt.get(key)
        if isinstance(value, str):
            return value
        if value is not None and hasattr(value, "name"):
            return value.name
    return "UNKNOWN"


def _leader(receipt) -> dict:
    data = receipt.get("consensus_data") or {}
    leader = data.get("leader_receipt") or {}
    if isinstance(leader, list):
        leader = leader[0] if leader else {}
    return leader


def _execution(receipt) -> str:
    value = _leader(receipt).get("execution_result")
    return value if isinstance(value, str) else str(value)


def _revert(receipt) -> str:
    result = _leader(receipt).get("result") or {}
    return json.dumps(result)[:400] if not isinstance(result, str) else result[:400]


def _votes(receipt) -> list:
    last = receipt.get("last_round") or {}
    votes = last.get("votes") or (receipt.get("consensus_data") or {}).get("votes") or {}
    if isinstance(votes, dict):
        return [str(v) for v in votes.values()]
    return [str(v) for v in votes]


def _rounds(receipt) -> int:
    data = receipt.get("consensus_data") or {}
    rounds = data.get("rounds") or receipt.get("rounds")
    return len(rounds) if isinstance(rounds, list) else 1


# -- the catalogue -------------------------------------------------------------

def origins(raw_base: str) -> dict:
    """The same commit, served by two origins, because a challenge that asks for
    two independent origins cannot be satisfied from one host."""
    prefix = "https://raw.githubusercontent.com/"
    if not raw_base.startswith(prefix):
        sys.exit("--raw-base must be a commit-pinned raw.githubusercontent.com URL")
    owner, repo, commit, rest = raw_base[len(prefix):].split("/", 3)
    return {"base": raw_base,
            "mirror": "https://cdn.jsdelivr.net/gh/" + owner + "/" + repo + "@" + commit
                      + "/" + rest}


def load(raw_base: str, deadline: str) -> tuple:
    challenges = json.loads((FIXTURES / "challenges.json").read_text(encoding="utf-8"))
    cases = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))
    filled = {name: json.dumps(spec, sort_keys=True).replace("{deadline}", deadline)
              for name, spec in challenges.items()}
    return (filled, cases)


def evidence_json(case: dict, hosts: dict) -> str:
    return json.dumps([{"url": hosts[entry["origin"]] + entry["path"],
                        "kind": entry["kind"], "sha256": entry["sha256"],
                        "label": entry["label"]} for entry in case["evidence"]])


# -- the phases ----------------------------------------------------------------

def phase_challenges(chain: Chain, challenges: dict):
    for name in sorted(challenges):
        step = "challenge:" + name
        entry = chain.send(step, "publisher", "publish_challenge", [challenges[name]])
        if "challenge_id" not in entry:
            page = chain.created(entry, step, "list_challenges", [0, 50])
            entry["challenge_id"] = page["ids"][-1]
            chain.transcript.put(step, entry)
        log("    " + name + " -> " + entry["challenge_id"])


def challenge_id(chain: Chain, name: str) -> str:
    return chain.transcript.get("challenge:" + name)["challenge_id"]


def challenge_hash(chain: Chain, name: str) -> str:
    return chain.read("get_definition_hash", [challenge_id(chain, name)])["definition_hash"]


def phase_cases(chain: Chain, cases: dict, hosts: dict):
    for case in cases["cases"]:
        name = case["case"]
        cid = challenge_id(chain, case["challenge"])
        chash = challenge_hash(chain, case["challenge"])
        file_step = "file:" + name
        entry = chain.send(file_step, case["wallet"], "submit_attempt",
                           [cid, chash, case["summary"], case["reference"],
                            case["claimed_impact"], evidence_json(case, hosts)])
        if "submission_id" not in entry:
            page = chain.created(entry, file_step, "list_submissions", [cid, 0, 50])
            entry["submission_id"] = page["ids"][-1]
            chain.transcript.put(file_step, entry)
        submission_id = entry["submission_id"]
        step = "resolve:" + name
        if chain.transcript.has(step):
            log("  skip " + step + " (recorded)")
            continue
        chain.send(step, "keeper", "resolve", [submission_id])
        record(chain, step, name, submission_id, case)

    contest_case = cases["contest_case"]
    submission_id = chain.transcript.get("file:" + contest_case)["submission_id"]
    step = "contest:" + contest_case
    if not chain.transcript.has(step):
        case = [c for c in cases["cases"] if c["case"] == contest_case][0]
        chain.send(step, case["wallet"], "contest", [submission_id])
        record(chain, step, contest_case + ":contest", submission_id, case, round_two=True)


def record(chain: Chain, step: str, label: str, submission_id: str, case: dict,
           round_two: bool = False):
    entry = chain.transcript.get(step)
    entry["submission_id"] = submission_id
    answer = chain.read("get_latest_resolution", [submission_id])
    if answer.get("found"):
        resolution = answer["resolution"]
        entry["resolution_id"] = resolution["resolution_id"]
        entry["observed_verdict"] = resolution["verdict"]
        entry["observed_reason"] = resolution["reason_code"]
        entry["observed_impact"] = resolution["impact"]
        entry["evidence_class"] = resolution["evidence_class"]
        entry["independent_origins"] = resolution["independent_origins"]
        entry["bytes_bound"] = resolution["bytes_bound"]
        entry["panel_state"] = resolution["panel_state"]
        entry["markers"] = resolution["markers"]
        entry["round"] = resolution["round"]
        entry["supersedes"] = resolution["supersedes"]
        entry["expected_verdict"] = case["expect_verdict"]
        entry["expected_reason"] = case["expect_reason"]
        entry["expected_impact"] = case["expect_impact"]
        held = (resolution["verdict"] == case["expect_verdict"]
                and resolution["reason_code"] == case["expect_reason"]
                and resolution["impact"] == case["expect_impact"])
        if round_two:
            held = resolution["round"] == 2 and resolution["supersedes"] != ""
            entry["expected_verdict"] = "a second reading, superseding the first"
        entry["held"] = held
        entry["note"] = case["note"]
        # the verdict a consumer reads, straight from the composability views
        entry["consumer_view"] = chain.read("is_exploit_confirmed", [submission_id])
    else:
        entry["held"] = False
        entry["observed_reason"] = "no resolution stored"
    chain.transcript.put(step, entry)
    log("    " + label + ": " + str(entry.get("observed_verdict")) + "/"
        + str(entry.get("observed_reason")) + "/" + str(entry.get("observed_impact"))
        + (" HELD" if entry["held"] else " MISSED"))


def wait_until(iso: str, what: str):
    target = time.mktime(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    while True:
        left = target - time.time()
        if left <= 5:
            return
        log("  waiting " + str(int(left) + 5) + "s for " + what)
        time.sleep(min(left + 5, 120))


def phase_settle(chain: Chain, cases: dict):
    """Finalise what has a verdict, so a consumer sees `final`, and lapse what was
    left unresolved."""
    for case in cases["cases"]:
        if not case.get("settle"):
            continue
        step = "file:" + case["case"]
        if not chain.transcript.has(step):
            continue
        submission_id = chain.transcript.get(step)["submission_id"]
        state = chain.read("get_submission", [submission_id])
        if state["status"] != "RESOLVED":
            continue
        settle_step = "finalize:" + case["case"]
        if chain.transcript.has(settle_step):
            continue
        wait_until(state["window_ends"], "the contest window of " + submission_id)
        entry = chain.send(settle_step, "keeper", "finalize", [submission_id])
        verdict = chain.read("get_verdict", [submission_id])
        entry["final"] = verdict["final"]
        entry["verdict"] = verdict["verdict"]
        entry["confirmed"] = verdict["confirmed"]
        entry["held"] = verdict["final"] is True
        chain.transcript.put(settle_step, entry)

    # one attempt is left to lapse: nobody resolved it inside its window
    step = "file:lapse"
    if chain.transcript.has(step):
        submission_id = chain.transcript.get(step)["submission_id"]
        state = chain.read("get_submission", [submission_id])
        if state["status"] == "PENDING":
            wait_until(state["window_ends"], "the resolve window of " + submission_id)
            entry = chain.send("lapse", "keeper", "lapse_submission", [submission_id])
            after = chain.read("get_submission", [submission_id])
            entry["submission_status"] = after["status"]
            entry["reason_code"] = after["reason_code"]
            entry["held"] = after["status"] == "CANCELLED" and after["reason_code"] \
                == "LAPSED"
            chain.transcript.put("lapse", entry)

    chain.transcript.data["stats"] = chain.read("get_stats")
    chain.transcript.save()
    log("  stats: " + json.dumps(chain.transcript.data["stats"]))


def phase_refusals(chain: Chain, cases: dict, hosts: dict):
    name = cases["cases"][0]["challenge"]
    cid = challenge_id(chain, name)
    chash = challenge_hash(chain, name)
    case = cases["cases"][0]
    evidence = evidence_json(case, hosts)
    other_evidence = json.dumps([{
        "url": hosts["base"] + "evidence/invariants.html", "kind": "LIVE", "sha256": "",
        "label": "The published invariant"}])
    outside = json.dumps([{"url": "https://attacker.example.com/my-own-report.json",
                           "kind": "LIVE", "sha256": "", "label": "My own report"}])

    chain.refuse("refuse:wrong_hash", "bob", "submit_attempt",
                 [cid, "00" * 32, "A summary of an attempt.", "0xa11ce", "HIGH",
                  other_evidence],
                 because="the challenge hash does not match the challenge")
    chain.refuse("refuse:unknown_challenge", "bob", "submit_attempt",
                 ["BC-999999", chash, "A summary.", "0xa11ce", "HIGH", other_evidence],
                 because="no such challenge")
    chain.refuse("refuse:outside_domains", "bob", "submit_attempt",
                 [cid, chash, "A summary.", "0xa11ce", "HIGH", outside],
                 because="the evidence must come from a source the challenge named")
    chain.refuse("refuse:unknown_band", "bob", "submit_attempt",
                 [cid, chash, "A summary.", "0xa11ce", "APOCALYPTIC", other_evidence],
                 because="the claimed impact must be one of the challenge's bands")
    chain.refuse("refuse:duplicate_submission", case["wallet"], "submit_attempt",
                 [cid, chash, case["summary"], case["reference"], case["claimed_impact"],
                  evidence],
                 because="this account already filed against this challenge")
    chain.refuse("refuse:cancel_with_submissions", "publisher", "cancel_challenge", [cid],
                 because="a challenge that already has submissions cannot be cancelled")
    chain.refuse("refuse:not_publisher_cancel", "bob", "cancel_challenge", [cid],
                 because="only the publisher cancels a challenge")
    first = chain.transcript.get("file:" + cases["cases"][0]["case"])["submission_id"]
    chain.refuse("refuse:double_resolution", "keeper", "resolve", [first],
                 because="a submission is resolved once")
    chain.refuse("refuse:stranger_contest", "stranger", "contest", [first],
                 because="only the attacker or the publisher contests a verdict")
    chain.refuse("refuse:stranger_withdraw", "stranger", "withdraw_submission", [first],
                 because="only the attacker withdraws their own submission")


def phase_lapse_setup(chain: Chain, cases: dict, hosts: dict):
    """File one attempt that is deliberately never resolved, so the settle phase
    can lapse it."""
    step = "file:lapse"
    if chain.transcript.has(step):
        return
    name = cases["cases"][0]["challenge"]
    cid = challenge_id(chain, name)
    chash = challenge_hash(chain, name)
    evidence = json.dumps([{"url": hosts["mirror"] + "evidence/invariants.html",
                            "kind": "LIVE", "sha256": "",
                            "label": "The published invariant"}])
    entry = chain.send(step, "stranger", "submit_attempt",
                       [cid, chash, "An attempt nobody will resolve.", "0xnever", "LOW",
                        evidence])
    if "submission_id" not in entry:
        page = chain.created(entry, step, "list_submissions", [cid, 0, 50])
        entry["submission_id"] = page["ids"][-1]
        chain.transcript.put(step, entry)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("--raw-base", required=True,
                        help="commit-pinned base URL for fixtures/, ending in a slash")
    parser.add_argument("--phase", default="full", choices=("full",) + PHASES)
    parser.add_argument("--transcript", default=None)
    args = parser.parse_args()
    if not args.raw_base.endswith("/"):
        sys.exit("--raw-base must end with a slash")

    hosts = origins(args.raw_base)
    path = pathlib.Path(args.transcript) if args.transcript else None
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        globals()["LOG"] = path.with_suffix(".log")
    transcript = Transcript(args.address, args.raw_base, path)
    deadline = transcript.data.get("deadline") or now_iso(DEADLINE_AFTER)
    transcript.data["deadline"] = deadline
    challenges, cases = load(args.raw_base, deadline)
    chain = Chain(args.address, transcript)
    log("contract " + args.address + " phase " + args.phase)

    phases = PHASES if args.phase == "full" else (args.phase,)
    for phase in phases:
        log("phase " + phase)
        if phase == "challenges":
            phase_challenges(chain, challenges)
        elif phase == "cases":
            phase_lapse_setup(chain, cases, hosts)
            phase_cases(chain, cases, hosts)
        elif phase == "settle":
            phase_settle(chain, cases)
        elif phase == "refusals":
            phase_refusals(chain, cases, hosts)
    log("summary " + json.dumps(transcript.summary()))


if __name__ == "__main__":
    main()
