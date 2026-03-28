import os
import json
import asyncio
import aiosqlite
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List

app = FastAPI(title="PIL Sovereign Identity Protocol API")

from webauthn_routes import router as webauthn_router
app.include_router(webauthn_router)

FRONTEND_URL = os.getenv("PIL_FRONTEND_URL", "http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = os.path.join(os.path.dirname(__file__), "pil_identities.db")
CIRCUITS_DIR = os.path.join(os.path.dirname(__file__), "circuits")

class IdentityResponse(BaseModel):
    secret_key: str
    public_hash: str

class VerifyRequest(BaseModel):
    proof: Dict[str, Any]
    public_signals: List[str]

@app.on_event("startup")
async def startup_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS identities (
                public_hash TEXT PRIMARY KEY
            )
        ''')
        await db.commit()

@app.post("/generate-identity", response_model=IdentityResponse)
async def generate_identity():
    script_path = os.path.join(CIRCUITS_DIR, "generate.js")
    
    process = await asyncio.create_subprocess_shell(
        "node generate.js",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=CIRCUITS_DIR
    )
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Failed to generate identity: {stderr.decode()}")
    
    try:
        data = json.loads(stdout.decode().strip())
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid output from identity generator")

    public_hash = data.get("public_hash")
    
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("INSERT OR IGNORE INTO identities (public_hash) VALUES (?)", (public_hash,))
        await db.commit()
        
    return data

@app.post("/verify-identity")
async def verify_identity(req: VerifyRequest):
    if not req.public_signals or len(req.public_signals) == 0:
        raise HTTPException(status_code=400, detail="Missing public signals")
        
    public_hash = req.public_signals[0]
    
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT 1 FROM identities WHERE public_hash = ?", (public_hash,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Identity not found in database")
                
    script_path = os.path.join(CIRCUITS_DIR, "verify.js")
    proof_str = json.dumps(req.proof)
    public_str = json.dumps(req.public_signals)
    
    proof_escaped = proof_str.replace('"', '\\"')
    public_escaped = public_str.replace('"', '\\"')
    process = await asyncio.create_subprocess_shell(
        f'node verify.js "{proof_escaped}" "{public_escaped}"',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=CIRCUITS_DIR
    )
    stdout, stderr = await process.communicate()
    
    if process.returncode == 0 and "OK" in stdout.decode():
        return {"status": "success", "message": "Identity verified successfully"}
    else:
        raise HTTPException(status_code=401, detail="Invalid Zero-Knowledge Proof")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
