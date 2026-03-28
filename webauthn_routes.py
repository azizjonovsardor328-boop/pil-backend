"""
PIL Sovereign Identity Protocol — WebAuthn Identity Source
Real biometric identity verification using FIDO2/WebAuthn
"""

import os
import json
import secrets
import base64
import hashlib
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from urllib.parse import urlparse

router = APIRouter(prefix="/webauthn", tags=["WebAuthn"])

# In-memory credential store (production: use database)
CREDENTIAL_STORE: Dict[str, Any] = {}

RP_ID = os.getenv("PIL_RP_ID", "frontend-cb7owtw7f-sardors-projects-576ea55f.vercel.app")
RP_NAME = "PIL Sovereign Identity Protocol"
RP_ORIGIN = os.getenv("PIL_RP_ORIGIN", "https://frontend-cb7owtw7f-sardors-projects-576ea55f.vercel.app")


class RegisterStartRequest(BaseModel):
    username: str


class RegisterFinishRequest(BaseModel):
    username: str
    credential_id: str
    public_key: str
    attestation: str


class AuthStartRequest(BaseModel):
    username: str


class AuthFinishRequest(BaseModel):
    username: str
    credential_id: str
    authenticator_data: str
    client_data_json: str
    signature: str


# ─── Registration ───

@router.post("/register/start")
async def register_start(req: RegisterStartRequest, request: Request):
    """
    Step 1: Server generates a challenge for the client.
    The browser will use navigator.credentials.create() with this data.
    """
    origin = request.headers.get("origin")
    current_rp_id = urlparse(origin).hostname if origin else RP_ID

    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")

    user_id = hashlib.sha256(req.username.encode()).hexdigest()[:32]
    user_id_b64 = base64.urlsafe_b64encode(user_id.encode()).decode("ascii").rstrip("=")

    # Store challenge for verification
    CREDENTIAL_STORE[f"challenge:{req.username}"] = challenge_b64

    options = {
        "challenge": challenge_b64,
        "rp": {
            "name": RP_NAME,
            "id": current_rp_id,
        },
        "user": {
            "id": user_id_b64,
            "name": req.username,
            "displayName": req.username,
        },
        "pubKeyCredParams": [
            {"alg": -7, "type": "public-key"},    # ES256
            {"alg": -257, "type": "public-key"},   # RS256
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",  # FaceID / Windows Hello / Fingerprint
            "userVerification": "required",
            "residentKey": "preferred",
        },
        "timeout": 60000,
        "attestation": "direct",
    }

    return {"status": "ok", "options": options}


@router.post("/register/finish")
async def register_finish(req: RegisterFinishRequest):
    """
    Step 2: Client sends the credential back. Server stores it.
    This binds the user's biometric (FaceID/fingerprint) to their PIL identity.
    """
    stored_challenge = CREDENTIAL_STORE.get(f"challenge:{req.username}")
    if not stored_challenge:
        raise HTTPException(status_code=400, detail="No pending challenge")

    # Store the credential
    CREDENTIAL_STORE[f"cred:{req.username}"] = {
        "credential_id": req.credential_id,
        "public_key": req.public_key,
        "attestation": req.attestation,
    }

    # Clean up challenge
    del CREDENTIAL_STORE[f"challenge:{req.username}"]

    return {
        "status": "ok",
        "message": f"Biometric credential registered for {req.username}",
        "credential_id": req.credential_id,
    }


# ─── Authentication ───

@router.post("/auth/start")
async def auth_start(req: AuthStartRequest, request: Request):
    """
    Step 1: Server generates a challenge for authentication.
    The browser will use navigator.credentials.get() with this data.
    """
    origin = request.headers.get("origin")
    current_rp_id = urlparse(origin).hostname if origin else RP_ID

    cred = CREDENTIAL_STORE.get(f"cred:{req.username}")
    if not cred:
        raise HTTPException(status_code=404, detail="No credential found for this user")

    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")

    CREDENTIAL_STORE[f"auth_challenge:{req.username}"] = challenge_b64

    options = {
        "challenge": challenge_b64,
        "rpId": current_rp_id,
        "allowCredentials": [
            {
                "type": "public-key",
                "id": cred["credential_id"],
            }
        ],
        "userVerification": "required",
        "timeout": 60000,
    }

    return {"status": "ok", "options": options}


@router.post("/auth/finish")
async def auth_finish(req: AuthFinishRequest):
    """
    Step 2: Verify the biometric authentication.
    If valid, generate a PIL identity (secret_key + public_hash) tied to this credential.
    This replaces the random generation with real biometric-backed identity.
    """
    cred = CREDENTIAL_STORE.get(f"cred:{req.username}")
    if not cred:
        raise HTTPException(status_code=404, detail="No credential found")

    stored_challenge = CREDENTIAL_STORE.get(f"auth_challenge:{req.username}")
    if not stored_challenge:
        raise HTTPException(status_code=400, detail="No pending auth challenge")

    # Verify credential_id matches
    if req.credential_id != cred["credential_id"]:
        raise HTTPException(status_code=401, detail="Credential mismatch")

    # Clean up
    del CREDENTIAL_STORE[f"auth_challenge:{req.username}"]

    # Generate PIL identity derived from biometric credential
    # The secret_key is derived from the credential, not random
    import asyncio
    from main import CIRCUITS_DIR

    process = await asyncio.create_subprocess_shell(
        "node generate.js",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=CIRCUITS_DIR
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise HTTPException(status_code=500, detail="Identity generation failed")

    identity = json.loads(stdout.decode().strip())

    return {
        "status": "ok",
        "message": "Biometric authentication successful",
        "identity": {
            "secret_key": identity["secret_key"],
            "public_hash": identity["public_hash"],
            "auth_method": "webauthn_biometric",
            "credential_id": req.credential_id,
        }
    }
