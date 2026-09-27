"""Reads against the canonical StudioNet deployment.

These tests do not re-run consensus: they check that the contract on chain is the
contract in this repository, that it answers, and that every verdict the live run
recorded is what the chain still holds - including through the views a downstream
consumer would use. One write is opt-in (`BREACHCOURT_LIVE_WRITES=1`), because it
sends a real transaction.

Each test is independently runnable:

    python -m pytest tests/integration -q
    python -m pytest tests/integration -q -k source_is_this_repository
"""

import base64
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

RECORD = ROOT / "deploy" / "deployment.json"
TRANSCRIPT = ROOT / "deploy" / "live_run_transcript.json"
CONTRACT = ROOT / "contracts" / "breachcourt.py"
RPC = "https://studio.genlayer.com/api"

pytestmark = pytest.mark.skipif(not RECORD.exists(),
                                reason="no canonical deployment recorded yet")


def rpc(method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    request = urllib.request.Request(RPC, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "breachcourt-integration"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                answer = json.loads(response.read().decode())
            if "error" in answer and "-32029" in json.dumps(answer["error"]):
                raise RuntimeError("rate limited")
            return answer
        except Exception:
            if attempt == 5:
                raise
            time.sleep(5 * (attempt + 1))


@pytest.fixture(scope="module")
def record():
    return json.loads(RECORD.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def client():
    import studionet_transport  # noqa: F401 - retries RPC transport failures
    from genlayer_py import create_account, create_client
    from genlayer_py.chains import studionet
    keys = json.loads((ROOT / ".data" / "demo_wallets.json").read_text(encoding="utf-8"))
    account = create_account(account_private_key=keys["keeper"])
    return create_client(chain=studionet, account=account, endpoint=RPC)


def read(client, record, method, args=None):
    return client.read_contract(address=record["contract_address"],
                                function_name=method, args=args or [])


def test_the_deployed_source_is_this_repository(record):
    answer = rpc("gen_getContractCode", [record["contract_address"]])
    raw = answer.get("result")
    deployed = base64.b64decode(raw) if isinstance(raw, str) and "\n" not in raw[:40] \
        else str(raw).encode()
    if hashlib.sha256(deployed).hexdigest() != record["source_sha256"]:
        deployed = str(raw).encode()
    assert hashlib.sha256(deployed).hexdigest() == record["source_sha256"]
    assert record["source_sha256"] == hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
    assert record["byte_identical"] is True


def test_the_schema_is_the_whole_surface(record):
    schema = rpc("gen_getContractSchema", [record["contract_address"]]).get("result") or {}
    methods = schema.get("methods") or {}
    assert len(methods) == 23
    for name in ("publish_challenge", "submit_attempt", "resolve", "contest", "finalize",
                 "lapse_submission", "is_exploit_confirmed", "get_verdict",
                 "get_evidence_status", "get_definition_hash"):
        assert name in methods


def test_the_config_on_chain_matches_the_contract(client, record):
    config = read(client, record, "get_config")
    assert config["contract_version"] == "0.1.0"
    assert config["payable"] is False
    for verdict in ("EXPLOIT_CONFIRMED", "EXPLOIT_REJECTED", "INCONCLUSIVE",
                    "EVIDENCE_UNAVAILABLE", "CANCELLED", "PENDING"):
        assert verdict in config["verdicts"]
    assert config["evidence_kinds"] == ["PINNED", "LIVE"]
    assert config["caps"]["evidence_items"] == 4


@pytest.mark.skipif(not TRANSCRIPT.exists(), reason="no live run recorded yet")
def test_every_verdict_the_run_recorded_is_still_on_chain(client, record):
    steps = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))["steps"]
    checked = 0
    for name, entry in sorted(steps.items()):
        if not name.startswith(("resolve:", "contest:")) or "resolution_id" not in entry:
            continue
        answer = read(client, record, "get_resolution", [entry["resolution_id"]])
        assert answer["found"], name
        resolution = answer["resolution"]
        assert resolution["verdict"] == entry["observed_verdict"], name
        assert resolution["reason_code"] == entry["observed_reason"], name
        assert resolution["impact"] == entry["observed_impact"], name
        checked += 1
    assert checked > 0


@pytest.mark.skipif(not TRANSCRIPT.exists(), reason="no live run recorded yet")
def test_the_consumer_views_agree_with_the_records(client, record):
    """What a monitor polls must agree with the full record behind it."""
    steps = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))["steps"]
    checked = 0
    for name, entry in sorted(steps.items()):
        if not name.startswith("resolve:") or "submission_id" not in entry:
            continue
        submission_id = entry["submission_id"]
        verdict = read(client, record, "get_verdict", [submission_id])
        confirmed = read(client, record, "is_exploit_confirmed", [submission_id])
        assert verdict["found"] and confirmed["found"], name
        assert confirmed["confirmed"] == (verdict["verdict"] == "EXPLOIT_CONFIRMED"), name
        assert confirmed["final"] == verdict["final"], name
        assert confirmed["verdict"] == verdict["verdict"], name
        status = read(client, record, "get_evidence_status", [submission_id])
        assert status["found"], name
        assert status["evidence_class"] == verdict["evidence_class"], name
        checked += 1
    assert checked > 0


@pytest.mark.skipif(not TRANSCRIPT.exists(), reason="no live run recorded yet")
def test_a_confirmed_exploit_rests_on_bound_bytes_and_independent_origins(client, record):
    steps = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))["steps"]
    confirmations = [e for n, e in steps.items()
                     if e.get("observed_verdict") == "EXPLOIT_CONFIRMED"]
    assert confirmations, "the run recorded no confirmation"
    for entry in confirmations:
        answer = read(client, record, "get_resolution", [entry["resolution_id"]])
        resolution = answer["resolution"]
        assert resolution["bytes_bound"] is True
        assert len(resolution["independent_origins"]) \
            >= resolution["min_independent_origins"]
        assert resolution["impact"] in ("LOW", "HIGH", "CRITICAL")
        assert all(item["compared"] for item in resolution["sources"])


@pytest.mark.skipif(os.environ.get("BREACHCOURT_LIVE_WRITES") != "1",
                    reason="set BREACHCOURT_LIVE_WRITES=1 to send one transaction")
def test_a_challenge_can_still_be_published(client, record):
    from genlayer_py.types import TransactionStatus
    templates = json.loads((ROOT / "fixtures" / "challenges.json")
                           .read_text(encoding="utf-8"))
    deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    text = json.dumps(templates["vaultlite"], sort_keys=True).replace("{deadline}",
                                                                     deadline)
    before = read(client, record, "get_stats")["challenges"]
    tx = client.write_contract(address=record["contract_address"],
                              function_name="publish_challenge", args=[text])
    client.wait_for_transaction_receipt(transaction_hash=tx,
                                       status=TransactionStatus.FINALIZED,
                                       interval=5000, retries=240)
    assert read(client, record, "get_stats")["challenges"] == before + 1
