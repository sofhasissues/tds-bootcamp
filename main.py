from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Literal, Any
import re

app = FastAPI()

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Action]
    environmentApproval: bool | None = None


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: Literal["preview", "production"]
    event: Literal["pull_request", "push"]
    ref: str
    workflow: Workflow
    image: Image


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/release-gate")
def release_gate(data: ReleaseRequest):
    violations = []

    # Permissions must match exactly, with no extra scopes.
    if data.workflow.permissions != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # Pull requests must use the safe pull_request trigger.
    if data.event == "pull_request" and data.workflow.trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # The test suite and full matrix must complete, without fail-fast.
    if (not data.workflow.testsPassed or
            not data.workflow.matrixComplete or
            data.workflow.failFast):
        violations.append("TESTS_INCOMPLETE")

    # First-party actions/* may use tags; all third-party actions need full SHAs.
    for action in data.workflow.actions:
        if action.owner != "actions" and not FULL_SHA.fullmatch(action.ref):
            violations.append("MUTABLE_ACTION")
            break

    if not data.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if data.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if data.image.secretMode not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")

    if data.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    if not data.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    if data.target == "production":
        if data.event != "push" or data.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if data.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
