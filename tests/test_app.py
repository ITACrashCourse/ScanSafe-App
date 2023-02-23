import pytest
import requests

def test_homepage():
    response = requests.get("http://127.0.0.1:5000/")
    assert response.status_code == 200