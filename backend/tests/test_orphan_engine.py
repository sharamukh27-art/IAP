from app.orphan_engine import evaluate_evidence
from app.orphan_models import OrphanState


def signals(**detected):
    names = {
        "official_eol_announcement",
        "support_end_date_passed",
        "updates_stopped",
        "maintenance_endpoint_unavailable",
        "security_certificate_expired",
        "unpatched_vulnerabilities",
    }
    return [
        {"signal": name, "detected": detected.get(name, False)}
        for name in sorted(names)
    ]


def test_single_unavailable_endpoint_is_not_an_orphan_candidate():
    state, reasons = evaluate_evidence(
        signals(maintenance_endpoint_unavailable=True)
    )
    assert state == OrphanState.SUPPORT_AT_RISK
    assert "1 distinct signals detected" in reasons[0]


def test_lack_of_updates_alone_is_not_an_orphan_candidate():
    state, _ = evaluate_evidence(signals(updates_stopped=True))
    assert state == OrphanState.SUPPORT_AT_RISK


def test_multiple_lifecycle_and_security_signals_become_candidate():
    state, _ = evaluate_evidence(
        signals(
            official_eol_announcement=True,
            support_end_date_passed=True,
            updates_stopped=True,
            maintenance_endpoint_unavailable=True,
        )
    )
    assert state == OrphanState.ORPHAN_CANDIDATE


def test_evidence_without_both_lifecycle_and_corroborating_groups_stays_at_risk():
    state, _ = evaluate_evidence(
        signals(
            maintenance_endpoint_unavailable=True,
            security_certificate_expired=True,
            unpatched_vulnerabilities=True,
        )
    )
    assert state == OrphanState.SUPPORT_AT_RISK
