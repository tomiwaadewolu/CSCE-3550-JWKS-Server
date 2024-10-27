#Name: Ireoluwatomiwa Adewolu
#euid: ija0023
#CSCE 3550.001
#Generating RSA Pair Keys
#Building Test Suite for JWKS Server
import pytest
import sqlite3
import datetime
from jwks_server import app, DB_FILE, init_db

#set up test client
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        init_db()  #initialize database per test
        yield client

def test_database_initialization():
    """Test that database initializes and has the correct data."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        assert count == 2  #should have two entries: one valid, one expired

def test_jwks_endpoint(client):
    """Test the JWKS endpoint returns the correct key information."""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    keys = response.json['keys']
    assert len(keys) == 1
    assert keys[0]["kid"] == "goodKID"

def test_auth_token_valid(client):
    """Test the /auth endpoint returns a valid token."""
    response = client.post('/auth')
    assert response.status_code == 200
    token = response.json.get("token")
    assert token is not None

def test_auth_token_expired(client):
    """Test the /auth endpoint returns an expired token when requested."""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    token = response.json.get("token")
    assert token is not None  #token should still be generated even if expired

def test_unsupported_method(client):
    """Test that an unsupported HTTP method returns a 405 error."""
    response = client.put('/auth')  #using PUT instead of POST
    assert response.status_code == 405
    assert response.json == {'error': 'Method not allowed'}

#ChatGPT was used to ask for steps to making a test suite and to help debug

#Examples of prompts used:
# -Please explain steps to building a test suite for python code
# -Please explain why some modules are undefined