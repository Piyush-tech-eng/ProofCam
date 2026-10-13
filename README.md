# ProofCam

ProofCam is a media-integrity proof of concept for resale listings. It reports file integrity, capture evidence, and optional AI-risk estimates as separate signals. A matching file hash proves byte-level correspondence to a record; it does not prove that the depicted scene is real.

## Current build

The Node API, browser demo, and native Android CameraX capture source are implemented. The API issues one-time challenges, validates ECDSA signatures over canonical payloads, stores signed manifests, and verifies submitted image bytes against a persistent demo registry. The UI reports file match, capture evidence, and AI-risk status independently. The marketplace preview updates its badge from the API's live verification response and labels the record source. The shared TypeScript SDK exposes a verifier abstraction and Solana Devnet account/manifest adapter; the API can produce an unsigned Anchor registration transaction when configured for Devnet.

The local registry is a demo substitute. It does not write to Solana or produce transaction signatures. Devnet registration still requires a deployed program, a wallet to sign and submit the returned transaction, and configured manifest storage. Immutable Anchor program source has been added, but WSL access is denied and Anchor CLI is not installed, so it has not been compiled or deployed. Android SDK is not installed here, so native source has not been built into an APK. Device-attestation validation and an AI detector are not configured.

## Run locally

Requirements: Node.js 20+ and pnpm.

Install and build:

    pnpm install
    pnpm build

Start each service in a separate terminal:

    pnpm dev:api
    pnpm dev:web

Open http://localhost:5173. Register an image, then verify the original bytes, a changed copy with the same capture ID, and another unregistered image. Local records are saved under .proofcam-data; remove that directory to reset the demo.

## Repository

- apps/api: challenge, package validation, local registry, and verification API.
- apps/web: browser signing and verification experience.
- apps/android-capture: native CameraX capture, exact-byte hashing, and Android Keystore signing.
- programs/proofcam: immutable Anchor capture registry source.
- packages/proofcam-client: shared contracts, RFC 8785 canonicalization, hashing, and package validation.
- tests/fixtures: image and cross-platform test vectors.

Device timestamps are device-supplied. Hardware attestation is not implemented in this browser demo, so its status is reported as unsupported. The optional detector is not configured, and its unavailable status does not change file integrity.

Never commit wallet keypairs, private keys, API tokens, or populated .env files.
