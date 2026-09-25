from __future__ import annotations
import os, shutil, tempfile
from abc import ABC, abstractmethod
from pathlib import Path
class StorageError(RuntimeError): pass
class ArtifactStorage(ABC):
    @abstractmethod
    def create(self,artifact_id:str)->None: ...
    @abstractmethod
    def put_file(self,artifact_id:str,name:str,source:Path)->None: ...
    @abstractmethod
    def get_file(self,artifact_id:str,name:str,destination:Path)->None: ...
    @abstractmethod
    def exists(self,artifact_id:str)->bool: ...
    @abstractmethod
    def delete(self,artifact_id:str)->None: ...
    @abstractmethod
    def materialize(self,artifact_id:str)->Path: ...
    def cleanup_materialized(self,path:Path)->None: shutil.rmtree(path,ignore_errors=True)
class LocalArtifactStorage(ArtifactStorage):
    def __init__(self,root:str|Path): self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
    def _dir(self,artifact_id:str)->Path: return self.root/artifact_id
    def _safe_name(self,name:str)->str:
        if name not in {"artifact.stok","artifact.stok.key"}: raise StorageError("Invalid artifact object")
        return name
    def create(self,artifact_id:str)->None: self._dir(artifact_id).mkdir(mode=0o700,exist_ok=False)
    def put_file(self,artifact_id:str,name:str,source:Path)->None:
        name=self._safe_name(name); target=self._dir(artifact_id)/name
        if not target.parent.is_dir(): raise StorageError("Artifact does not exist")
        shutil.copyfile(source,target); target.chmod(0o600)
    def get_file(self,artifact_id:str,name:str,destination:Path)->None:
        name=self._safe_name(name); source=self._dir(artifact_id)/name
        if not source.is_file(): raise FileNotFoundError(name)
        shutil.copyfile(source,destination)
    def exists(self,artifact_id:str)->bool: return self._dir(artifact_id).is_dir()
    def delete(self,artifact_id:str)->None: shutil.rmtree(self._dir(artifact_id),ignore_errors=True)
    def materialize(self,artifact_id:str)->Path:
        if not self.exists(artifact_id): raise FileNotFoundError(artifact_id)
        return self._dir(artifact_id)
class S3ArtifactStorage(ArtifactStorage):
    def __init__(self,bucket:str,prefix:str="smart-token/artifacts",endpoint_url:str|None=None):
        try: import boto3
        except ImportError as exc: raise StorageError("S3 backend requires boto3") from exc
        if not bucket: raise StorageError("SMART_TOKEN_S3_BUCKET is required")
        self.bucket=bucket; self.prefix=prefix.strip("/"); self.client=boto3.client("s3",endpoint_url=endpoint_url or None)
    def _key(self,artifact_id:str,name:str="")->str:
        if name and name not in {"artifact.stok","artifact.stok.key"}: raise StorageError("Invalid artifact object")
        base=f"{self.prefix}/{artifact_id}" if self.prefix else artifact_id
        return f"{base}/{name}" if name else base
    def create(self,artifact_id:str)->None: return None
    def put_file(self,artifact_id:str,name:str,source:Path)->None: self.client.upload_file(str(source),self.bucket,self._key(artifact_id,name),ExtraArgs={"ServerSideEncryption":"AES256"})
    def get_file(self,artifact_id:str,name:str,destination:Path)->None: self.client.download_file(self.bucket,self._key(artifact_id,name),str(destination))
    def exists(self,artifact_id:str)->bool:
        r=self.client.list_objects_v2(Bucket=self.bucket,Prefix=self._key(artifact_id)+"/",MaxKeys=1); return bool(r.get("Contents"))
    def delete(self,artifact_id:str)->None:
        r=self.client.list_objects_v2(Bucket=self.bucket,Prefix=self._key(artifact_id)+"/"); objects=[{"Key":x["Key"]} for x in r.get("Contents",[])]
        if objects: self.client.delete_objects(Bucket=self.bucket,Delete={"Objects":objects})
    def materialize(self,artifact_id:str)->Path:
        if not self.exists(artifact_id): raise FileNotFoundError(artifact_id)
        path=Path(tempfile.mkdtemp(prefix=f"smart-token-{artifact_id}-"))
        try:
            for name in ("artifact.stok","artifact.stok.key"): self.get_file(artifact_id,name,path/name)
            return path
        except Exception: shutil.rmtree(path,ignore_errors=True); raise
def build_storage()->ArtifactStorage:
    backend=os.getenv("SMART_TOKEN_STORAGE_BACKEND","local").lower()
    if backend=="local": return LocalArtifactStorage(os.getenv("SMART_TOKEN_STORAGE","./data/artifacts"))
    if backend=="s3": return S3ArtifactStorage(os.getenv("SMART_TOKEN_S3_BUCKET",""),os.getenv("SMART_TOKEN_S3_PREFIX","smart-token/artifacts"),os.getenv("SMART_TOKEN_S3_ENDPOINT_URL") or None)
    raise StorageError(f"Unsupported storage backend: {backend}")
