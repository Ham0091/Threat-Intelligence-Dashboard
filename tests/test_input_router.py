"""Unit tests for route_input(), is_valid_query(), and sanitize_input()."""
import pytest


@pytest.fixture(autouse=True)
def _ctx(app):
    with app.app_context():
        yield


class TestRouteInput:
    def test_valid_ipv4(self):
        from app import route_input
        result = route_input('8.8.8.8')
        assert result['valid'] is True
        assert result['query_type'] == 'ipv4'

    def test_invalid_ipv4_octet(self):
        from app import route_input
        result = route_input('999.0.0.1')
        assert result['valid'] is False

    def test_valid_ipv6(self):
        from app import route_input
        result = route_input('::1')
        assert result['valid'] is True
        assert result['query_type'] == 'ipv6'

    def test_valid_domain(self):
        from app import route_input
        result = route_input('example.com')
        assert result['valid'] is True
        assert result['query_type'] == 'domain'

    def test_valid_url(self):
        from app import route_input
        result = route_input('https://example.com/path?q=1')
        assert result['valid'] is True
        assert result['query_type'] == 'url'

    def test_unrecognised_input(self):
        from app import route_input
        result = route_input('not_a_valid_input!!')
        assert result['valid'] is False


class TestIsValidQuery:
    def test_empty_string(self):
        from app import is_valid_query
        assert is_valid_query('') is False

    def test_too_long(self):
        from app import is_valid_query
        assert is_valid_query('a' * 256) is False

    def test_valid_ip(self):
        from app import is_valid_query
        assert is_valid_query('1.2.3.4') is True

    def test_valid_domain(self):
        from app import is_valid_query
        assert is_valid_query('sub.example.co.uk') is True

    def test_bad_octet(self):
        from app import is_valid_query
        assert is_valid_query('256.1.1.1') is False


class TestSanitizeInput:
    def test_clean_input_passes(self):
        from app import sanitize_input
        ok, msg = sanitize_input('8.8.8.8')
        assert ok is True
        assert msg == ''

    def test_semicolon_rejected(self):
        from app import sanitize_input
        ok, msg = sanitize_input('8.8.8.8; rm -rf /')
        assert ok is False
        assert 'semicolon' in msg

    def test_backtick_rejected(self):
        from app import sanitize_input
        ok, msg = sanitize_input('example.com`id`')
        assert ok is False

    def test_pipe_rejected(self):
        from app import sanitize_input
        ok, msg = sanitize_input('example.com|whoami')
        assert ok is False

    def test_null_byte_rejected(self):
        from app import sanitize_input
        ok, msg = sanitize_input('example.com\x00extra')
        assert ok is False
