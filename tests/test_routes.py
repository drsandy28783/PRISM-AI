import os
import sys
import types
from unittest.mock import MagicMock
import pytest

@pytest.fixture(scope='session', autouse=True)
def fake_firebase():
    firebase_admin = types.ModuleType('firebase_admin')
    firebase_admin.initialize_app = lambda *args, **kwargs: None

    credentials = types.ModuleType('credentials')
    credentials.Certificate = lambda data: None
    firebase_admin.credentials = credentials

    firestore_mod = types.ModuleType('firestore')
    firestore_mod.client = lambda: MagicMock()
    firestore_mod.transactional = lambda f: f
    firebase_admin.firestore = firestore_mod

    auth_mod = types.ModuleType('auth')
    firebase_admin.auth = auth_mod

    sys.modules['firebase_admin'] = firebase_admin
    sys.modules['firebase_admin.credentials'] = credentials
    sys.modules['firebase_admin.firestore'] = firestore_mod
    sys.modules['firebase_admin.auth'] = auth_mod
    yield
    for m in ['firebase_admin', 'firebase_admin.credentials', 'firebase_admin.firestore', 'firebase_admin.auth']:
        sys.modules.pop(m, None)

@pytest.fixture
def client(fake_firebase):
    os.environ['SECRET_KEY'] = 'test-secret'
    import importlib
    app_module = importlib.import_module('app')
    app = app_module.app
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_login_page_accessible(client):
    resp = client.get('/login')
    assert resp.status_code == 200


def test_add_patient_requires_login(client):
    resp = client.get('/add_patient')
    # should redirect to login
    assert resp.status_code == 302
    assert '/login' in resp.headers.get('Location', '')


def test_add_patient_logged_in(client):
    with client.session_transaction() as sess:
        sess['user_id'] = 'uid1'
        sess['is_admin'] = 0
        sess['approved'] = 1
    resp = client.get('/add_patient')
    assert resp.status_code == 200

