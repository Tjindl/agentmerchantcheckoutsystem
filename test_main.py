"""Tests for the Gatekeeper's /transact endpoint."""
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import owner  # generates the owner's keys, writes public_key.pem, signs a passport
from main import app

client = TestClient(app)


def transact(passport, amount, category):
    return client.post(
        "/transact",
        headers={"Authorization": f"Bearer {passport}"},
        json={"amount": amount, "category": category},
    )


def test_valid_purchase_is_approved():
    response = transact(owner.passport, 50, "cloud_compute")
    assert response.status_code == 200
    assert response.json()["status"] == "approved"


def test_purchase_over_max_spend_is_rejected():
    response = transact(owner.passport, 150, "cloud_compute")
    assert response.status_code == 403
    assert response.json()["detail"] == "Amount exceeds max_spend"


def test_purchase_in_wrong_category_is_rejected():
    response = transact(owner.passport, 50, "groceries")
    assert response.status_code == 403
    assert response.json()["detail"] == "Category not allowed"


def test_passport_signed_by_someone_else_is_rejected():
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {"user_id": "usr_99", "max_spend": 1_000_000, "allowed_category": "cloud_compute"},
        attacker_key,
        algorithm="RS256",
    )
    response = transact(forged, 50, "cloud_compute")
    assert response.status_code == 401
