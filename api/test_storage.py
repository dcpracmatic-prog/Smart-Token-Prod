from pathlib import Path
from api.storage import LocalArtifactStorage
def test_local_storage_roundtrip(tmp_path:Path):
    storage=LocalArtifactStorage(tmp_path/"artifacts"); artifact_id="a"*32; storage.create(artifact_id)
    source=tmp_path/"source.bin"; source.write_bytes(b"secret-payload"); storage.put_file(artifact_id,"artifact.stok",source)
    out=tmp_path/"out.bin"; storage.get_file(artifact_id,"artifact.stok",out); assert out.read_bytes()==b"secret-payload"; assert storage.exists(artifact_id)
    materialized=storage.materialize(artifact_id); assert (materialized/"artifact.stok").read_bytes()==b"secret-payload"; storage.cleanup_materialized(materialized); storage.delete(artifact_id); assert not storage.exists(artifact_id)
