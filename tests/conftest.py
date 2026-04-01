import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dashboard')))

@pytest.fixture
def app():
    import app as flask_module
    flask_module.app.config["TESTING"] = True
    yield flask_module.app

@pytest.fixture
def client(app):
    return app.test_client()