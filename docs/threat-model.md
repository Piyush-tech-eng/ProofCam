# ProofCam threat model (POC)

## Protected properties

- Exact-byte image hash is not silently altered by resizing, re-encoding, or metadata removal.
- Signed payload and package hashes are deterministic and independently verifiable.
- Capture IDs are random 32-byte values and map to immutable PDA records.
- Wallet approval is required to pay for and submit an on-chain registration.
- Location is opt-in and defaults to absent.

## Threats and current limits

- A user can submit an edited or synthetic image and sign it as a browser upload. The signature proves control of the key, not sensor origin.
- Browser keys are temporary and software-held. Android keys are Keystore-held, but the API does not validate an attestation chain or hardware security level.
- Device timestamps can be incorrect. Solana time is registration time.
- No hash match is an unknown result, not proof of fraud.
- AI risk is unavailable until an independently evaluated detector is configured.
- Local demo records can be edited by the host running the API. They are not blockchain evidence.
- Public RPC, public IPFS gateways, and local JSON persistence can be unavailable, rate-limited, or inconsistent. The verifier reports unavailable when required reads fail.
- Challenges are held in memory and limited by expiry and single-use state; a production service needs shared durable nonce storage, request throttling, key revocation, and abuse monitoring.
- The development Android manifest allows cleartext HTTP to reach local emulators. Replace this with HTTPS and an environment-specific network security policy before distribution.

## Explicit non-claims

File match does not prove a real-world event. A valid key signature does not prove the camera sensor produced the image. Device attestation does not by itself prove scene truth. Detector scores are estimates, not authenticity decisions.
