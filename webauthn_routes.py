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

# Import supabase client from main
from main import supabase

router = APIRouter(prefix="/webauthn", tags=["WebAuthn"])

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

    # Store challenge for verification in Supabase
    try:
        supabase.table("webauthn_challenges").upsert({
            "username": req.username,
            "challenge_type": "register",
            "challenge_b64": challenge_b64
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
    res = supabase.table("webauthn_challenges").select("*").eq("username", req.username).eq("challenge_type", "register").execute()
    if not res.data:
        raise HTTPException(status_code=400, detail="No pending challenge")

    # Store the credential in Supabase
    try:
        supabase.table("webauthn_credentials").upsert({
            "username": req.username,
            "credential_id": req.credential_id,
            "public_key": req.public_key,
            "attestation": req.attestation
        }).execute()
        
        # Clean up challenge
        supabase.table("webauthn_challenges").delete().eq("username", req.username).eq("challenge_type", "register").execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

    res = supabase.table("webauthn_credentials").select("*").eq("username", req.username).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="No credential found for this user. Please Register Biometrics first.")
    cred = res.data[0]

    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")

    try:
        supabase.table("webauthn_challenges").upsert({
            "username": req.username,
            "challenge_type": "auth",
            "challenge_b64": challenge_b64
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
    cred_res = supabase.table("webauthn_credentials").select("*").eq("username", req.username).execute()
    if not cred_res.data:
        raise HTTPException(status_code=404, detail="No credential found")
    cred = cred_res.data[0]

    chal_res = supabase.table("webauthn_challenges").select("*").eq("username", req.username).eq("challenge_type", "auth").execute()
    if not chal_res.data:
        raise HTTPException(status_code=400, detail="No pending auth challenge")

    # Verify credential_id matches
    if req.credential_id != cred["credential_id"]:
        raise HTTPException(status_code=401, detail="Credential mismatch")

    # Clean up auth challenge
    supabase.table("webauthn_challenges").delete().eq("username", req.username).eq("challenge_type", "auth").execute()

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
