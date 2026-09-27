"""The lifecycle, the verdicts and the views a consumer reads.

Each test drives the contract the way a caller would - publish a challenge, file
an attempt, resolve it, contest it, finalise it - and checks what the contract
stored, not what the harness said.
"""

from tests.direct import support as s

LATER = "2026-09-28T14:00:00Z"
MUCH_LATER = "2026-09-29T14:00:00Z"


# -- the challenge -------------------------------------------------------------

def test_a_challenge_is_published_with_its_hash(court, direct_vm, direct_alice):
    challenge_id = s.published(court, direct_vm, direct_alice)
    info = court.get_challenge(challenge_id)
    assert info["found"] and challenge_id == "BC-000001"
    assert info["publisher"] == direct_alice.as_hex.lower()
    assert info["status"] == "OPEN" and info["submission_count"] == 0
    assert len(info["definition_hash"]) == 64
    assert info["challenge"]["target_name"] == "VaultLite"
    assert info["spec_version"] == 1


def test_the_stored_challenge_is_the_canonical_form(court, direct_vm, direct_alice, mod):
    challenge_id = s.published(court, direct_vm, direct_alice)
    info = court.get_challenge(challenge_id)
    assert info["definition_hash"] == mod._sha256_hex(mod._canonical(info["challenge"]))
    assert court.get_definition_hash(challenge_id)["definition_hash"] \
        == info["definition_hash"]


def test_challenge_ids_run_in_order(court, direct_vm, direct_alice):
    first = s.published(court, direct_vm, direct_alice)
    second = s.published(court, direct_vm, direct_alice)
    assert (first, second) == ("BC-000001", "BC-000002")
    assert court.list_challenges(0, 10)["ids"] == [first, second]


def test_a_challenge_with_no_attempts_can_be_withdrawn(court, direct_vm, direct_alice):
    challenge_id = s.published(court, direct_vm, direct_alice)
    assert court.get_challenge_status(challenge_id, s.NOW)["may_cancel"] is True
    assert court.cancel_challenge(challenge_id) == "CANCELLED"
    status = court.get_challenge_status(challenge_id, s.NOW)
    assert status["effective_status"] == "CANCELLED"
    assert status["accepting_submissions"] is False


def test_a_challenge_closes_at_its_deadline(court, direct_vm, direct_alice):
    challenge_id = s.published(court, direct_vm, direct_alice)
    assert court.get_challenge_status(challenge_id, s.NOW)["accepting_submissions"] is True
    late = court.get_challenge_status(challenge_id, "2026-10-06T12:00:00Z")
    assert late["effective_status"] == "CLOSED"
    assert late["status"] == "OPEN" and late["accepting_submissions"] is False


def test_get_config_publishes_the_vocabulary(court):
    config = court.get_config()
    assert config["contract_version"] == "0.1.0"
    assert config["payable"] is False
    for verdict in ("EXPLOIT_CONFIRMED", "EXPLOIT_REJECTED", "INCONCLUSIVE",
                    "EVIDENCE_UNAVAILABLE", "CANCELLED", "PENDING"):
        assert verdict in config["verdicts"]
    assert "EXPLOIT_SHOWN" in config["reason_codes"]
    assert config["evidence_kinds"] == ["PINNED", "LIVE"]
    assert config["caps"]["evidence_items"] == 4


# -- the submission ------------------------------------------------------------

def test_an_attempt_commits_to_the_specification_it_read(court, direct_vm, direct_alice,
                                                         direct_bob, mod):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    submission = court.get_submission(submission_id)
    assert submission["found"] and submission_id == "AT-000001"
    assert submission["attacker"] == direct_bob.as_hex.lower()
    assert submission["challenge_hash"] == challenge_hash
    assert submission["status"] == "PENDING" and submission["verdict"] == "PENDING"
    assert submission["evidence_count"] == 3
    assert [i["evidence_id"] for i in submission["evidence"]] == ["E1", "E2", "E3"]
    assert submission["claims_are_untested"] is True
    assert court.get_challenge(challenge_id)["submission_count"] == 1


def test_the_evidence_commitment_is_over_the_list_it_returns(court, direct_vm,
                                                             direct_alice, direct_bob, mod):
    """Evidence is bound at filing and no write changes it, so the commitment and
    the list can never describe different things."""
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, _r = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                   challenge_hash)
    submission = court.get_submission(submission_id)
    assert submission["evidence_commitment"] == mod._sha256_hex(
        mod._canonical(submission["evidence"]))
    assert submission["evidence_digests"] == [i["sha256"] for i in submission["evidence"]]
    s.panel(direct_vm, s.confirmed_said())
    direct_vm.sender = direct_bob
    court.contest(submission_id)
    after = court.get_submission(submission_id)
    assert after["evidence_commitment"] == submission["evidence_commitment"]
    assert after["evidence"] == submission["evidence"]


def test_an_attempt_needs_the_matching_specification_hash(court, direct_vm, direct_alice):
    challenge_id = s.published(court, direct_vm, direct_alice)
    s.serve_all(direct_vm)
    with direct_vm.expect_revert("challenge_hash does not match"):
        court.submit_attempt(challenge_id, "00" * 32, "A summary", "0xa11ce", "HIGH",
                             s.evidence_json(s.standard_items()))


def test_one_attempt_per_account_per_challenge(court, direct_vm, direct_alice, direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    first = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    with direct_vm.expect_revert("already filed " + first):
        s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)


def test_an_attacker_withdraws_their_own_attempt(court, direct_vm, direct_alice,
                                                 direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    assert court.withdraw_submission(submission_id) == "CANCELLED"
    submission = court.get_submission(submission_id)
    assert submission["status"] == "CANCELLED" and submission["verdict"] == "CANCELLED"
    assert submission["reason_code"] == "WITHDRAWN"
    assert court.is_exploit_confirmed(submission_id)["confirmed"] is False


# -- the verdicts --------------------------------------------------------------

def test_a_confirmed_exploit_records_its_band_and_what_it_rested_on(court, direct_vm,
                                                                    direct_alice,
                                                                    direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, resolution_id = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                              challenge_hash)
    record = court.get_resolution(resolution_id)["resolution"]
    assert record["verdict"] == "EXPLOIT_CONFIRMED"
    assert record["reason_code"] == "EXPLOIT_SHOWN"
    assert record["impact"] == "HIGH"
    assert record["evidence_class"] == "EVIDENCE_REACHABLE"
    assert record["independent_origins"] == ["state.example.net", "traces.example.org"]
    assert record["min_independent_origins"] == 2
    assert record["bytes_bound"] is True
    assert record["corroboration_compared"] is False
    assert record["mode"] == "RESOLVE" and record["round"] == 1
    assert record["supersedes"] == ""
    verdict = court.get_verdict(submission_id)
    assert verdict["verdict"] == "EXPLOIT_CONFIRMED" and verdict["impact"] == "HIGH"
    assert verdict["rounds"] == 1 and verdict["final"] is False


def test_the_claimed_impact_is_recorded_as_a_claim_not_as_the_verdict(court, direct_vm,
                                                                     direct_alice,
                                                                     direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, resolution_id = s.resolved(
        court, direct_vm, direct_bob, challenge_id, challenge_hash,
        subjects=s.confirmed_said(impact="LOW"), claimed_impact="CRITICAL")
    record = court.get_resolution(resolution_id)["resolution"]
    assert record["claimed_impact"] == "CRITICAL"
    assert record["impact"] == "LOW"
    assert court.get_submission(submission_id)["claimed_impact"] == "CRITICAL"


def test_each_rejection_reason_reaches_the_record(court, direct_vm, direct_alice,
                                                  direct_bob, direct_charlie,
                                                  direct_accounts):
    s.published(court, direct_vm, direct_alice)
    s.serve_all(direct_vm)
    cases = (
        ({"attack": "NOT_SHOWN"}, "EXPLOIT_REJECTED", "ATTACK_NOT_SHOWN"),
        ({"reached": "NOT_SHOWN"}, "EXPLOIT_REJECTED", "PROHIBITED_STATE_NOT_REACHED"),
        ({"reached": "CONTRADICTED"}, "EXPLOIT_REJECTED", "EVIDENCE_CONTRADICTS_CLAIM"),
        ({"caller_role": "NOT_MET"}, "EXPLOIT_REJECTED", "REQUIREMENT_NOT_MET"),
        ({"attack": "UNCLEAR"}, "INCONCLUSIVE", "ATTACK_UNCLEAR"),
        ({"reached": "UNCLEAR"}, "INCONCLUSIVE", "PROHIBITED_STATE_UNCLEAR"),
        ({"caller_role": "UNCLEAR"}, "INCONCLUSIVE", "REQUIREMENT_UNCLEAR"),
        ({"consistency": "CONTRADICTORY"}, "INCONCLUSIVE", "EVIDENCE_CONTRADICTORY"),
        ({"impact": "UNCLEAR"}, "INCONCLUSIVE", "IMPACT_UNCLEAR"),
        ({"impact": "NONE"}, "INCONCLUSIVE", "IMPACT_UNCLEAR"),
    )
    wallets = [direct_bob, direct_charlie] + list(direct_accounts[3:])
    for index, (overrides, verdict, reason) in enumerate(cases):
        wallet = wallets[index % len(wallets)]
        other = s.published(court, direct_vm, direct_alice, spec_version=index + 1)
        other_hash = court.get_challenge(other)["definition_hash"]
        submission_id, resolution_id = s.resolved(
            court, direct_vm, wallet, other, other_hash,
            subjects=s.confirmed_said(**overrides))
        record = court.get_resolution(resolution_id)["resolution"]
        assert (record["verdict"], record["reason_code"]) == (verdict, reason), overrides
        assert court.is_exploit_confirmed(submission_id)["confirmed"] is False


def test_an_optional_requirement_not_met_does_not_reject(court, direct_vm, direct_alice,
                                                         direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    _sid, resolution_id = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                     challenge_hash,
                                     subjects=s.confirmed_said(permitted="NOT_MET"))
    record = court.get_resolution(resolution_id)["resolution"]
    assert record["verdict"] == "EXPLOIT_CONFIRMED"


def test_no_readable_evidence_is_unavailable_never_a_confirmation(court, direct_vm,
                                                                  direct_alice,
                                                                  direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    direct_vm.clear_mocks()
    s.serve_all(direct_vm, {s.TRACE_URL: None, s.STATE_URL: None, s.DOCS_URL: None})
    resolution_id = court.resolve(submission_id)
    record = court.get_resolution(resolution_id)["resolution"]
    assert record["verdict"] == "EVIDENCE_UNAVAILABLE"
    assert record["reason_code"] == "NO_EVIDENCE_READABLE"
    assert record["evidence_class"] == "EVIDENCE_UNAVAILABLE"
    assert record["panel_state"] == "SKIPPED"
    assert [x["status"] for x in record["sources"]] == ["NOT_FOUND"] * 3


def test_a_verdict_is_final_only_after_its_contest_window(court, direct_vm, direct_alice,
                                                          direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, _r = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                   challenge_hash)
    assert court.get_verdict(submission_id)["final"] is False
    with direct_vm.expect_revert("the contest window closes"):
        court.finalize(submission_id)
    direct_vm.warp(LATER)
    assert court.finalize(submission_id) == "FINAL"
    verdict = court.get_verdict(submission_id)
    assert verdict["final"] is True and verdict["confirmed"] is True
    assert court.get_submission(submission_id)["finalized_at"] == LATER


def test_a_contest_supersedes_and_can_overturn(court, direct_vm, direct_alice, direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, first = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                      challenge_hash)
    assert court.get_stats()["confirmed"] == 1
    s.panel(direct_vm, s.confirmed_said(reached="NOT_SHOWN"))
    direct_vm.sender = direct_alice
    second = court.contest(submission_id)
    record = court.get_resolution(second)["resolution"]
    assert record["mode"] == "CONTEST" and record["round"] == 2
    assert record["supersedes"] == first
    assert record["verdict"] == "EXPLOIT_REJECTED"
    assert court.get_verdict(submission_id)["verdict"] == "EXPLOIT_REJECTED"
    assert court.get_stats()["confirmed"] == 0
    history = court.get_history(submission_id)["rounds"]
    assert [r["verdict"] for r in history] == ["EXPLOIT_CONFIRMED", "EXPLOIT_REJECTED"]
    assert [r["mode"] for r in history] == ["RESOLVE", "CONTEST"]


def test_an_attempt_nobody_resolved_lapses(court, direct_vm, direct_alice, direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    with direct_vm.expect_revert("the resolve window closes"):
        court.lapse_submission(submission_id)
    direct_vm.warp(LATER)
    assert court.get_actions(submission_id, LATER)["may_lapse"] is True
    assert court.lapse_submission(submission_id) == "CANCELLED"
    submission = court.get_submission(submission_id)
    assert submission["status"] == "CANCELLED" and submission["reason_code"] == "LAPSED"


# -- what a consumer reads -----------------------------------------------------

def test_the_evidence_status_view_answers_without_internal_storage(court, direct_vm,
                                                                   direct_alice,
                                                                   direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id, _r = s.resolved(court, direct_vm, direct_bob, challenge_id,
                                   challenge_hash)
    status = court.get_evidence_status(submission_id)
    assert status["evidence_class"] == "EVIDENCE_REACHABLE"
    assert [i["evidence_id"] for i in status["items"]] == ["E1", "E2", "E3"]
    assert all(i["status"] == "RETRIEVED" for i in status["items"])
    assert all(i["compared"] for i in status["items"])
    assert status["bytes_bound"] is True
    assert status["independent_origins"] == ["state.example.net", "traces.example.org"]
    assert status["markers"] == []


def test_the_evidence_status_view_answers_before_any_resolution(court, direct_vm,
                                                                direct_alice, direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    status = court.get_evidence_status(submission_id)
    assert status["evidence_class"] == ""
    assert [i["status"] for i in status["items"]] == ["", "", ""]
    assert status["bytes_bound"] is False


def test_get_actions_reports_what_may_happen(court, direct_vm, direct_alice, direct_bob):
    challenge_id = s.published(court, direct_vm, direct_alice)
    challenge_hash = court.get_challenge(challenge_id)["definition_hash"]
    s.serve_all(direct_vm)
    submission_id = s.filed(court, direct_vm, direct_bob, challenge_id, challenge_hash)
    actions = court.get_actions(submission_id, s.NOW)
    assert actions["may_resolve"] and actions["may_withdraw"]
    assert not actions["may_contest"] and not actions["may_finalize"]
    s.panel(direct_vm, s.confirmed_said())
    court.resolve(submission_id)
    actions = court.get_actions(submission_id, s.NOW)
    assert actions["may_contest"] and not actions["may_resolve"]
    assert court.get_actions(submission_id, LATER)["may_finalize"] is True
    assert court.get_actions(submission_id, LATER)["may_contest"] is False


def test_the_listings_and_stats_hold(court, direct_vm, direct_alice, direct_bob,
                                     direct_charlie):
    first = s.published(court, direct_vm, direct_alice)
    first_hash = court.get_challenge(first)["definition_hash"]
    second = s.published(court, direct_vm, direct_alice, spec_version=2)
    second_hash = court.get_challenge(second)["definition_hash"]
    s.serve_all(direct_vm)
    a = s.filed(court, direct_vm, direct_bob, first, first_hash)
    b = s.filed(court, direct_vm, direct_charlie, second, second_hash)
    assert court.list_submissions(first, 0, 10)["ids"] == [a]
    assert court.list_submissions("", 0, 10)["ids"] == [a, b]
    assert court.list_submissions("BC-999999", 0, 10)["ids"] == []
    stats = court.get_stats()
    assert stats["challenges"] == 2 and stats["submissions"] == 2
    assert stats["resolutions"] == 0 and stats["confirmed"] == 0


def test_unknown_records_answer_not_found(court):
    assert court.get_challenge("BC-999999")["found"] is False
    assert court.get_definition_hash("BC-999999")["found"] is False
    assert court.get_challenge_status("BC-999999", s.NOW)["found"] is False
    assert court.get_submission("AT-999999")["found"] is False
    assert court.get_verdict("AT-999999")["found"] is False
    assert court.get_evidence_status("AT-999999")["found"] is False
    assert court.get_resolution("RS-999999")["found"] is False
    assert court.get_latest_resolution("AT-999999")["found"] is False
    assert court.get_history("AT-999999")["found"] is False
    assert court.get_actions("AT-999999", s.NOW)["found"] is False
    unknown = court.is_exploit_confirmed("AT-999999")
    assert unknown["found"] is False and unknown["confirmed"] is False \
        and unknown["final"] is False
