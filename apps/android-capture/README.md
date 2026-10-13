# ProofCam Capture for Android

This native CameraX app captures JPEG bytes into the app's private Pictures directory, hashes those exact bytes, signs the canonical version-1 payload with an Android Keystore P-256 key, and asks the ProofCam API to validate and register the manifest.

The current API registration uses the local demo registry. The app does not yet ask a Solana wallet to sign a transaction, and the server reports device attestation as unsupported. The saved private image stays on the phone; the app sends only the signed package and hashes.

## Build

Open this directory in Android Studio, install Android SDK 36, and sync the Gradle project. The app uses JDK 17 bytecode and requires Android API 24 or newer. The machine used to scaffold this project has no Android SDK, so an APK has not been built here.

CameraX is pinned to 1.6.2 and AndroidX Activity to 1.13.0. Change API_BASE in app/src/main/java/com/proofcam/capture/MainActivity.java for a physical test phone; the default 10.0.2.2:3000 targets the Android emulator and the local API.

## Capture flow

1. CameraX writes the capture output to an app-private file.
2. SHA-256 is computed from the saved file bytes.
3. A fresh server challenge is included in the signed payload.
4. The Android Keystore EC key signs the RFC 8785 canonical payload.
5. The API validates the signature and records the manifest in local demo mode.

Location is not requested or shared. A Keystore signature identifies possession of the app key; without validated Android key-attestation evidence it does not establish a hardware security level or prove sensor origin.
