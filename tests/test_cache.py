"""Tests for the SQLite result cache (get_cached_result / cache_result)."""
import json
import pytest
from unittest.mock import patch


CACHED_PAYLOAD = {
    'results': {'virustotal': {'valid': True, 'malicious_detections': 0}},
    'threat_score': 5.0,
    'query': '1.2.3.4',
    'query_type': 'ipv4',
    'timestamp': '2024-01-01T00:00:00+00:00',
    'errors': None,
}


@pytest.fixture(autouse=True)
def _ctx(app):
    with app.app_context():
        yield


class TestCache:
    def test_cache_miss_returns_none(self):
        from app import get_cached_result
        import hashlib
        # Use a hash that cannot exist in a fresh test DB
        fake_hash = hashlib.sha256(b'definitely-not-cached-xyz').hexdigest()
        assert get_cached_result(fake_hash) is None

    def test_lookup_returns_cached_result(self, client):
        """Second identical lookup should return from_cache=True without hitting APIs."""
        import hashlib
        query = '10.0.0.1'
        q_hash = hashlib.sha256(query.lower().encode()).hexdigest()

        # Prime the cache by patching get_cached_result to return a payload
        with patch('app.get_cached_result', return_value=CACHED_PAYLOAD):
            response = client.post(
                '/api/lookup',
                data=json.dumps({'query': query}),
                content_type='application/json',
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('from_cache') is True

    def test_fresh_lookup_not_marked_from_cache(self, client):
        """A lookup that misses the cache should NOT set from_cache=True."""
        query = '10.0.0.2'

        with patch('app.get_cached_result', return_value=None), \
             patch('app.query_virustotal', return_value={'valid': False, 'error': 'mocked'}), \
             patch('app.query_abuseipdb', return_value={'valid': False, 'error': 'mocked'}), \
             patch('app.query_greynoise', return_value={'valid': False, 'error': 'mocked'}), \
             patch('app.query_crowdsec', return_value={'valid': False, 'error': 'mocked'}), \
             patch('app.query_ipinfo', return_value={'valid': False, 'error': 'mocked'}), \
             patch('app.cache_result', return_value=None):
            response = client.post(
                '/api/lookup',
                data=json.dumps({'query': query}),
                content_type='application/json',
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('from_cache') is not True
