# Smart Token HTTP API

HTTP boundary for Smart-Token-Prod v0.10.5. The API keeps the cryptographic core in `smart_token_prod` and adds authenticated artifact operations plus pluggable persistence.

## Storage
- `local`: filesystem storage for development or a single host.
- `s3`: S3/S3-compatible object storage with server-side AES-256 encryption on upload.
- S3 artifacts are temporarily materialized for SDK operations and cleaned afterward.
- The Smart Token master secret is never persisted by this layer.

## Endpoints
- `GET /healthz`
- `GET /v1/status`
- `POST /v1/artifacts`
- `POST /v1/artifacts/{artifact_id}/open`
- `GET /v1/artifacts/{artifact_id}/friction`

Protected endpoints require `Authorization: Bearer <SMART_TOKEN_API_KEY>`. Protect/open also require `X-Smart-Token-Master`.

## Run
```bash
pip install -r api/requirements.txt
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

For production, use TLS at the platform edge, a secret manager, proxy log redaction, rate limiting, and appropriate object-storage controls. KMS/HSM integration remains a separate deployment concern.
