"""Tests for the /api/lookup rate limit (30 requests per hour per IP)."""
import json
import pytest
from unittest.mock import patch

CACHED_PAYLOAD = {
    'results': {'virustotal': {'valid': True, 'malicious_detections': 0}},
    'threat_score': 0.0,
    'query': '10.42.42.42',
    'query_type': 'ipv4',
    'timestamp': '2024-01-01T00:00:00+00:00',
    'errors': None,
    'from_cache': True,
}

UNIQUE_IP = '10.42.42.42'


@pytest.fixture(autouse=True)
def _ctx(app):
    with app.app_context():
        yield


class TestRateLimit:
    def _do_request(self, client):
        return client.post(
            '/api/lookup',
            data=json.dumps({'query': '1.2.3.4'}),
            content_type='application/json',
            environ_base={'REMOTE_ADDR': UNIQUE_IP},
        )

    def test_within_limit_returns_200(self, client):
        """A single request from a unique IP should succeed (200 or 200 from cache)."""
        with patch('app.get_cached_result', return_value=CACHED_PAYLOAD):
            resp = self._do_request(client)
        assert resp.status_code == 200

    def test_rate_limit_triggers_429(self, client):
        """After 30 requests, the 31st should be rate-limited (429)."""
        statuses = []
        with patch('app.get_cached_result', return_value=CACHED_PAYLOAD):
            for _ in range(32):
                resp = self._do_request(client)
                statuses.append(resp.status_code)

        assert 429 in statuses, f"Expected a 429 after 30 requests; got statuses: {set(statuses)}"

    def test_rate_limit_response_has_error_key(self, client):
        """The 429 response body should contain an 'error' key."""
        with patch('app.get_cached_result', return_value=CACHED_PAYLOAD):
            for _ in range(31):
                resp = self._do_request(client)

        assert resp.status_code == 429
        data = resp.get_json()
        assert 'error' in data
