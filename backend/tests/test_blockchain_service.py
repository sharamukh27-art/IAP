import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.blockchain_service import (
    BlockchainUnavailable,
    LocalBlockchain,
    verify_maintainer_signature,
)
from app.main import app


def test_ed25519_verifies_exact_firmware_bytes():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    package_bytes = b'{"format":"synthetic-firmware","firmware_version":"2.0.9"}'
    signature = base64.b64encode(private_key.sign(package_bytes)).decode()

    assert verify_maintainer_signature(public_key, package_bytes, signature) is None
    with pytest.raises(BlockchainUnavailable, match="signature is invalid"):
        verify_maintainer_signature(public_key, package_bytes + b" ", signature)


def test_blockchain_status_reports_missing_local_deployment(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "BLOCKCHAIN_DEPLOYMENT_FILE", str(tmp_path / "not-deployed.json")
    )
    client = TestClient(app)
    response = client.get("/api/blockchain/status")
    assert response.status_code == 200
    assert response.json()["available"] is False
    assert "not deployed" in response.json()["reason"]
    history = client.get("/api/blockchain/history")
    client.close()
    assert history.status_code == 200
    assert history.json()["available"] is False
    assert history.json()["records"] == []


def test_chain_client_rejects_non_loopback_rpc(tmp_path):
    deployment = tmp_path / "deployment.json"
    deployment.write_text("{}")
    with pytest.raises(BlockchainUnavailable, match="loopback"):
        LocalBlockchain(rpc_url="http://example.invalid:8545", deployment_path=deployment)
