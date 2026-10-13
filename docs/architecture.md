# ProofCam architecture

## Implemented paths

- Browser upload: browser-generated P-256 key -> one-time API challenge -> canonical signed capture package -> persistent local demo registry.
- Android source: CameraX writes JPEG bytes to app-private storage -> SHA-256 over the saved bytes -> Android Keystore P-256 signature -> API challenge and manifest validation.
- Verifier SDK: accepts a registry/manifest adapter, compares exact file bytes, verifies manifest commitment and device signature, and returns independent file-integrity, attestation, and AI-risk statuses.
- Solana adapter: derives the capture PDA, reads and decodes Anchor account data, performs a hash-index lookup through RPC, fetches manifests from an IPFS gateway, and can construct an unsigned registration transaction.

## Registry modes

local_demo is the default. It stores records and manifests in .proofcam-data and does not imply a blockchain transaction.

solana_devnet requires SOLANA_RPC_URL, the deployed PROOFCAM_PROGRAM_ID, and MANIFEST_STORAGE_API_URL. The API can validate/pin a manifest, construct an unsigned registration transaction for a wallet, and verify confirmed records from RPC. The current Android app still uses the local index endpoint; wallet signing and live Devnet submission remain to be connected.

## Trust boundaries

The image is hashed on the capturing client and is not uploaded during manifest validation. The public key, signed payload, and manifest are public metadata. The blockchain stores hashes and metadata references, not image bytes.

A valid signature proves that the corresponding private key signed the payload. Android hardware attestation and Play Integrity validation are not implemented. A device timestamp is user-device input; the chain timestamp is registration time. Neither signal proves the depicted scene happened.

The local and browser flows are demonstrators. Production use requires a deployed and audited program, wallet transaction approval, durable content-addressed manifest pinning, nonce/key lifecycle controls, rate limits, indexer operations, and deployment-specific security review.
