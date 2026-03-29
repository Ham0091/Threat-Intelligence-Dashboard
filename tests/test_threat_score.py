"""Unit tests for calculate_threat_score()."""
import pytest


def make_vt(malicious=0, reputation=0):
    return {'valid': True, 'malicious_detections': malicious, 'reputation_score': reputation}


def make_abuse(confidence=0):
    return {'valid': True, 'abuse_confidence_score': confidence}


def make_greynoise(classification='unknown', noise=False):
    return {'valid': True, 'classification': classification, 'noise': noise, 'riot': False, 'name': None, 'last_seen': None}


def make_crowdsec(is_bad=False, overall_score=0, behaviors=None):
    return {'valid': True, 'is_bad': is_bad, 'overall_score': overall_score, 'behaviors': behaviors or [], 'last_seen': None}


def make_urlhaus(threat_score=0):
    return {'valid': True, 'threat_score': threat_score}


@pytest.fixture(autouse=True)
def _import(app):
    """Ensure app context so module-level constants are initialised."""
    with app.app_context():
        yield


class TestThreatScore:
    def test_zero_score_when_no_results(self):
        from app import calculate_threat_score
        assert calculate_threat_score({}) == 0.0

    def test_vt_malicious_raises_score(self):
        from app import calculate_threat_score
        # 10 malicious x 3 = 30 raw VT score;  30 x 0.30 weight = 9.0
        results = {'virustotal': make_vt(malicious=10)}
        score = calculate_threat_score(results)
        assert score > 0

    def test_abuseipdb_full_confidence_contributes(self):
        from app import calculate_threat_score
        results = {'abuseipdb': make_abuse(confidence=100)}
        score = calculate_threat_score(results)
        # 100 x 0.30 = 30
        assert abs(score - 30.0) < 1e-6

    def test_greynoise_malicious_adds_20(self):
        from app import calculate_threat_score
        results = {'greynoise': make_greynoise(classification='malicious')}
        score = calculate_threat_score(results)
        assert abs(score - 20.0) < 1e-6

    def test_greynoise_noise_adds_10(self):
        from app import calculate_threat_score
        results = {'greynoise': make_greynoise(classification='unknown', noise=True)}
        score = calculate_threat_score(results)
        assert abs(score - 10.0) < 1e-6

    def test_greynoise_malicious_and_noise_adds_30(self):
        from app import calculate_threat_score
        results = {'greynoise': make_greynoise(classification='malicious', noise=True)}
        score = calculate_threat_score(results)
        assert abs(score - 30.0) < 1e-6

    def test_crowdsec_is_bad_adds_25(self):
        from app import calculate_threat_score
        results = {'crowdsec': make_crowdsec(is_bad=True)}
        score = calculate_threat_score(results)
        assert abs(score - 25.0) < 1e-6

    def test_crowdsec_high_score_adds_15(self):
        from app import calculate_threat_score
        results = {'crowdsec': make_crowdsec(is_bad=False, overall_score=75)}
        score = calculate_threat_score(results)
        assert abs(score - 15.0) < 1e-6

    def test_combined_score_capped_at_100(self):
        from app import calculate_threat_score
        results = {
            'virustotal': make_vt(malicious=100, reputation=-100),
            'abuseipdb': make_abuse(confidence=100),
            'greynoise': make_greynoise(classification='malicious', noise=True),
            'crowdsec': make_crowdsec(is_bad=True),
            'urlhaus': make_urlhaus(threat_score=100),
        }
        score = calculate_threat_score(results)
        assert score <= 100.0

    def test_invalid_source_ignored(self):
        from app import calculate_threat_score
        results = {'virustotal': {'valid': False, 'error': 'timeout'}}
        assert calculate_threat_score(results) == 0.0
