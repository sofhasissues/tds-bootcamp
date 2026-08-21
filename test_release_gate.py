from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

SAFE = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"}
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}


def test_safe_preview_promotes():
    response = client.post("/release-gate", json=SAFE)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}


def test_multiple_failures_are_all_reported():
    payload = {
        **SAFE,
        "workflow": {
            **SAFE["workflow"],
            "permissions": {"contents": "write"},
            "trigger": "pull_request_target",
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [
                {"owner": "evilcorp", "name": "deploy", "ref": "v1"}
            ]
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "copy",
            "criticalVulnerabilities": 2,
            "digestPinned": False
        }
    }
    result = client.post("/release-gate", json=payload).json()
    assert result["decision"] == "block"
    assert set(result["violations"]) == {
        "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
        "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
        "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE"
    }


def test_production_requires_main_push_and_approval():
    payload = {
        **SAFE,
        "target": "production",
        "event": "push",
        "ref": "refs/heads/dev",
        "workflow": {**SAFE["workflow"], "environmentApproval": False}
    }
    assert set(client.post("/release-gate", json=payload).json()["violations"]) == {
        "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"
    }
