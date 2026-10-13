# 90-second local demo

1. Start pnpm dev:api and pnpm dev:web; open http://localhost:5173.
2. Register a JPEG. Explain that the browser creates a temporary key, signs a challenge-bound payload, and the local API verifies the signature before storing a demo record.
3. Verify the same file using the displayed capture ID. Show the file-match result separately from capture evidence. The record source says local_demo; no chain transaction exists.
4. Change one byte or export an edited copy and verify using the same capture ID. The result should be a mismatch while the manifest remains independently inspectable.
5. Choose a separate unregistered image and verify without a capture ID. The result is unknown.
6. Point out that AI risk is not assessed unless a detector is configured, and that no status proves the depicted scene is real.

## Devnet demo (after deployment and wallet integration)

Use an Android phone/emulator with a Solana wallet, a pinned IPFS-compatible manifest provider, an RPC endpoint, and the deployed program ID. The current API can produce an unsigned registration transaction and verify a confirmed PDA, but the app still needs its Mobile Wallet Adapter signing/submission step wired before this path is end-to-end.
