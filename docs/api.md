# ProofCam API

Base URL defaults to http://localhost:3000. JSON errors use an object with code and message fields.

| Method | Path | Behavior |
|---|---|---|
| GET | /health | API and configured registry mode |
| GET | /v1/config | Registry, chain availability, manifest-storage configuration |
| POST | /v1/captures/challenge | Issue a five-minute, one-time nonce |
| POST | /v1/captures/validate | Validate package schema, challenge, key fingerprint, and ECDSA signature; store content-addressed manifest |
| POST | /v1/captures/transaction | Build an unsigned Devnet registration transaction for an external wallet |
| POST | /v1/captures/index | In local mode create a demo record; in Devnet mode confirm an existing on-chain record |
| GET | /v1/captures/:captureId | Read one record |
| GET | /v1/captures/by-hash/:sha256 | Find records by file hash |
| GET | /v1/manifests/:cid | Retrieve a stored or gateway-pinned signed package |
| POST | /v1/verify | Verify exact uploaded bytes; body contains file_base64, optional capture_id, optional include_ai_risk |

The browser upload endpoint accepts files up to MAX_UPLOAD_BYTES (10 MiB by default). Challenge and registry maps are for the local POC; use a persistent, rate-limited challenge store and a proper indexer before exposing a production API.

To enable the live adapter, copy .env.example to .env, deploy the Anchor program, set the resulting program ID, select PROOFCAM_REGISTRY_MODE=solana_devnet, and configure an IPFS-compatible pinning API. A wallet must sign the transaction returned from /v1/captures/transaction; the API never holds wallet secrets.
