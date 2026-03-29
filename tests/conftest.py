import sys
import os
import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Provide dummy API keys so startup validation doesn't fail
os.environ.setdefault('VT_API_KEY', 'test_vt_key')
os.environ.setdefault('ABUSEIPDB_API_KEY', 'test_abuse_key')
os.environ.setdefault('SHODAN_API_KEY', 'test_shodan_key')
os.environ.setdefault('OTXAPI_KEY', 'test_otx_key')
os.environ.setdefault('URLHAUS_API_KEY', 'public')


@pytest.fixture(scope='session')
def app():
    from app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_limiter(app):
    """Reset Flask-Limiter storage before each test to avoid cross-test pollution."""
    from app import limiter
    try:
        limiter.reset()
    except Exception:
        pass
    yield
