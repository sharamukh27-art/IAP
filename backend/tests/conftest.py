import pytest
from fastapi import Request

from app.auth import get_current_user
from app.main import app

@pytest.fixture(autouse=True)
def isolate_tests_from_deployed_chain(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "BLOCKCHAIN_DEPLOYMENT_FILE",
        str(tmp_path / "no-test-chain-deployment.json"),
    )
    async def test_user(request: Request):
        body = {}
        if request.method not in {"GET", "HEAD"}:
            content_type = request.headers.get("content-type", "")
            try:
                body = (
                    dict(await request.form())
                    if content_type.startswith("multipart/form-data")
                    else await request.json()
                )
            except (ValueError, TypeError):
                body = {}
        path = request.url.path
        if path == "/api/patches" and request.method == "POST":
            role, user_id = "security_researcher", str(body.get("researcher_id", "researcher-ada"))
        elif path.endswith("/reviews") and request.method == "POST":
            role, user_id = "independent_reviewer", str(body.get("reviewer_id", "reviewer-ada"))
        elif path.endswith("/attestations") and request.method == "POST":
            role, user_id = "independent_reviewer", str(body.get("reviewer_id", "reviewer-ada"))
        elif path.endswith("/release") and request.method == "POST":
            user_id = str(body.get("actor_id", "patch-admin-demo"))
            role = "administrator" if user_id == "patch-admin-demo" else "security_researcher"
        elif path.endswith("/claims") and request.method == "POST":
            role, user_id = "administrator", str(body.get("submitted_by", "simulated-admin"))
        elif path.endswith("/finalize") and request.method == "POST":
            role, user_id = "administrator", str(body.get("actor", "simulated-admin"))
        elif path == "/api/orphans/simulations" and request.method == "POST":
            role, user_id = "administrator", str(body.get("actor", "simulated-admin"))
        else:
            role, user_id = "administrator", "simulated-admin"
        return {
            "user_id": user_id,
            "display_name": "Test User",
            "role": role,
            "active": True,
            "manufacturer": None,
            "device_ids": [],
        }

    app.dependency_overrides[get_current_user] = test_user
    yield
    app.dependency_overrides.pop(get_current_user, None)
