"""The live-run fixtures, checked against the deployed code.

The panel's readings cannot be checked here - that is what the live run is for -
but everything around them can: each challenge template parses, each declared
digest is the digest of the document that will be served, every referenced
document exists unless the case is about its absence, the injected document trips
the marker scan and no honest one does.
"""

import hashlib
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
BASE = "https://raw.githubusercontent.com/example/breachcourt/0000000/fixtures/"
MIRROR = "https://cdn.jsdelivr.net/gh/example/breachcourt@0000000/fixtures/"
ORIGINS = {"base": BASE, "mirror": MIRROR}

CHALLENGES = json.loads((FIXTURES / "challenges.json").read_text(encoding="utf-8"))
CASES = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))
MISSING = ("evidence/missing-trace.json", "evidence/missing-state.html")
INJECTED = ("evidence/injected-state.html",)
DEADLINE = "2026-12-31T00:00:00Z"


def filled(template: dict) -> str:
    return json.dumps(template).replace("{deadline}", DEADLINE)


@pytest.mark.parametrize("name", sorted(CHALLENGES))
def test_every_challenge_template_parses(mod, name):
    error, spec = mod._parse_challenge(filled(CHALLENGES[name]))
    assert error == "", name
    assert spec["min_independent_origins"] <= len(spec["evidence_domains"])
    assert sorted(spec["evidence_domains"]) == sorted(CASES["origins"])


def test_the_catalogue_is_coherent(mod):
    config_verdicts = ("EXPLOIT_CONFIRMED", "EXPLOIT_REJECTED", "INCONCLUSIVE",
                       "EVIDENCE_UNAVAILABLE")
    for case in CASES["cases"]:
        assert case["challenge"] in CHALLENGES, case["case"]
        assert case["expect_verdict"] in config_verdicts, case["case"]
        assert case["expect_reason"] in mod.REASON_CODES, case["case"]
        spec = CHALLENGES[case["challenge"]]
        bands = [b["band"] for b in spec["severity_bands"]]
        assert case["claimed_impact"] in bands, case["case"]
        if case["expect_impact"]:
            assert case["expect_impact"] in bands, case["case"]
        assert mod._text_error(case["summary"], mod.SUMMARY_CAP, "s", True) == "", \
            case["case"]
        assert 1 <= len(case["evidence"]) <= mod.MAX_EVIDENCE, case["case"]
    assert CASES["contest_case"] in [c["case"] for c in CASES["cases"]]


def test_at_least_one_case_of_each_verdict_is_exercised():
    verdicts = {c["expect_verdict"] for c in CASES["cases"]}
    assert verdicts == {"EXPLOIT_CONFIRMED", "EXPLOIT_REJECTED", "INCONCLUSIVE",
                        "EVIDENCE_UNAVAILABLE"}
    reasons = {c["expect_reason"] for c in CASES["cases"]}
    for reason in ("EXPLOIT_SHOWN", "PROHIBITED_STATE_NOT_REACHED", "ATTACK_NOT_SHOWN",
                   "EVIDENCE_CONTRADICTORY", "NO_EVIDENCE_READABLE",
                   "EVIDENCE_DIGEST_MISMATCH", "SOURCE_ADDRESSES_ADJUDICATOR",
                   "CORROBORATION_SHORT"):
        assert reason in reasons, reason


def test_every_declared_digest_is_the_digest_of_the_document_that_is_served():
    for case in CASES["cases"]:
        for entry in case["evidence"]:
            path = entry["path"]
            if entry["kind"] != "PINNED" or path in MISSING:
                continue
            served = (FIXTURES / path).read_bytes()
            digest = hashlib.sha256(served).hexdigest()
            if case["expect_reason"] == "EVIDENCE_DIGEST_MISMATCH":
                continue        # that case declares a wrong digest on purpose
            assert entry["sha256"] == digest, (case["case"], path)


def test_a_mismatch_case_declares_a_digest_that_cannot_match():
    case = [c for c in CASES["cases"]
            if c["expect_reason"] == "EVIDENCE_DIGEST_MISMATCH"][0]
    wrong = [e for e in case["evidence"]
             if e["sha256"] != hashlib.sha256(
                 (FIXTURES / e["path"]).read_bytes()).hexdigest()]
    assert len(wrong) == 1


def test_every_named_document_exists_unless_the_case_is_about_its_absence():
    for case in CASES["cases"]:
        for entry in case["evidence"]:
            exists = (FIXTURES / entry["path"]).exists()
            assert exists != (entry["path"] in MISSING), (case["case"], entry["path"])


def test_no_document_is_unreferenced():
    served = {str(p.relative_to(FIXTURES)).replace("\\", "/")
              for p in (FIXTURES / "evidence").iterdir()}
    referenced = {e["path"] for c in CASES["cases"] for e in c["evidence"]}
    assert served - referenced == set()


def test_every_document_says_it_is_a_fixture():
    for path in (FIXTURES / "evidence").iterdir():
        text = path.read_text(encoding="utf-8")
        assert "TEST / DEMONSTRATION ONLY" in text, path.name
        assert "NOT FOR PRODUCTION" in text, path.name


@pytest.mark.parametrize("path", sorted(str(p.relative_to(FIXTURES)).replace("\\", "/")
                                       for p in (FIXTURES / "evidence").iterdir()))
def test_the_marker_scan_agrees_with_what_each_document_is(mod, path):
    raw = (FIXTURES / path).read_text(encoding="utf-8")
    html = path.endswith(".html")
    source = {"status": "RETRIEVED", "title": mod._title_of(raw, html)}
    normalized = mod._normalize(raw, html)
    found = mod._markers(source, normalized, raw)
    assert bool(found) == (path in INJECTED), (path, found)


def test_a_case_resting_on_one_origin_is_marked_as_such():
    """The corroboration cases have to be built from the origins they claim, or
    they prove nothing about the floor."""
    short = [c for c in CASES["cases"] if c["expect_reason"] == "CORROBORATION_SHORT"]
    assert short
    for case in short:
        origins = {e["origin"] for e in case["evidence"]}
        kinds = {e["kind"] for e in case["evidence"]}
        assert len(origins) == 1 or kinds == {"LIVE"}, case["case"]
    confirmed = [c for c in CASES["cases"]
                 if c["expect_verdict"] == "EXPLOIT_CONFIRMED"][0]
    assert len({e["origin"] for e in confirmed["evidence"]}) == 2
    assert all(e["kind"] == "PINNED" for e in confirmed["evidence"])
