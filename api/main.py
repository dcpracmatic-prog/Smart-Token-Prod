from __future__ import annotations
import os, secrets, tempfile
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import Response
from smart_token_prod.sdk import artifact_friction_status, is_available, open_artifact, protect_artifact, status as sdk_status
from .storage import ArtifactStorage, build_storage
APP_NAME="Smart Token API"
API_KEY=os.getenv("SMART_TOKEN_API_KEY")
MAX_UPLOAD_BYTES=int(os.getenv("SMART_TOKEN_MAX_UPLOAD_BYTES", str(50*1024*1024)))
app=FastAPI(title=APP_NAME, version="0.10.5", docs_url="/docs", redoc_url="/redoc")
storage: ArtifactStorage=build_storage()
def require_api_key(authorization: Optional[str]=Header(default=None)) -> None:
    if not API_KEY: raise HTTPException(503,"API authentication is not configured")
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Missing bearer token")
    if not secrets.compare_digest(authorization[7:].strip(), API_KEY): raise HTTPException(401,"Invalid bearer token")
def validate_artifact_id(artifact_id:str)->str:
    if len(artifact_id)!=32 or any(c not in "0123456789abcdef" for c in artifact_id): raise HTTPException(404,"Artifact not found")
    return artifact_id
async def save_upload(upload:UploadFile,destination:Path)->None:
    total=0
    with destination.open("wb") as out:
        while True:
            chunk=await upload.read(1024*1024)
            if not chunk: break
            total+=len(chunk)
            if total>MAX_UPLOAD_BYTES:
                destination.unlink(missing_ok=True); raise HTTPException(413,"Upload exceeds configured size limit")
            out.write(chunk)
@app.get("/healthz")
def healthz(): return {"ok":True,"storage_backend":os.getenv("SMART_TOKEN_STORAGE_BACKEND","local"),"smart_token_available":is_available()}
@app.get("/v1/status",dependencies=[Depends(require_api_key)])
def status(): return sdk_status()
@app.post("/v1/artifacts",dependencies=[Depends(require_api_key)])
async def protect(file:UploadFile=File(...),x_smart_token_master:str=Header(...,alias="X-Smart-Token-Master")):
    if not x_smart_token_master: raise HTTPException(400,"Master secret is required")
    if not is_available(): raise HTTPException(503,"Smart Token crypto stack unavailable")
    artifact_id=secrets.token_hex(16)
    try:
        storage.create(artifact_id)
        with tempfile.TemporaryDirectory(prefix="smart-token-upload-") as tmp:
            source=Path(tmp)/"source.bin"; await save_upload(file,source)
            stok,key=protect_artifact(source,master_secret=x_smart_token_master)
            storage.put_file(artifact_id,"artifact.stok",stok); storage.put_file(artifact_id,"artifact.stok.key",key)
    except HTTPException: storage.delete(artifact_id); raise
    except Exception as exc: storage.delete(artifact_id); raise HTTPException(500,"Artifact protection failed") from exc
    return {"artifact_id":artifact_id,"filename":file.filename,"status":"PROTECTED"}
@app.post("/v1/artifacts/{artifact_id}/open",dependencies=[Depends(require_api_key)])
def open_endpoint(artifact_id:str,x_smart_token_master:str=Header(...,alias="X-Smart-Token-Master")):
    validate_artifact_id(artifact_id)
    if not x_smart_token_master: raise HTTPException(400,"Master secret is required")
    if not storage.exists(artifact_id): raise HTTPException(404,"Artifact not found")
    materialized=None
    try:
        materialized=storage.materialize(artifact_id)
        plaintext,info=open_artifact(materialized/"artifact.stok",master_secret=x_smart_token_master,key_path=materialized/"artifact.stok.key",reveal_friction=False)
    except FileNotFoundError as exc: raise HTTPException(500,"Artifact storage is incomplete") from exc
    except Exception as exc: raise HTTPException(500,"Artifact processing failed") from exc
    finally:
        if materialized is not None: storage.cleanup_materialized(materialized)
    if plaintext is None: return Response(status_code=403,content=b"DENIED")
    return Response(content=plaintext,media_type="application/octet-stream",headers={"X-Smart-Token-Status":str(info.get("status","OPEN"))})
@app.get("/v1/artifacts/{artifact_id}/friction",dependencies=[Depends(require_api_key)])
def friction(artifact_id:str):
    validate_artifact_id(artifact_id)
    if not storage.exists(artifact_id): raise HTTPException(404,"Artifact not found")
    materialized=None
    try:
        materialized=storage.materialize(artifact_id); return artifact_friction_status(materialized/"artifact.stok")
    except Exception as exc: raise HTTPException(500,"Unable to inspect artifact") from exc
    finally:
        if materialized is not None: storage.cleanup_materialized(materialized)
