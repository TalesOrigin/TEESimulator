# TEESimulator Embedded — Rootless Attestation Library

An Android library that brings the full TEESimulator attestation engine into any
APK **without requiring root**. The library bundles the Rust KeyMint reference TA
(Trusted Application) and provides a simple Java/Kotlin API to generate
keybox-signed attestation certificate chains.

## How it works

Unlike the root-based TEESimulator module (which injects into `keystore2` to
intercept attestation system-wide), the embedded library runs the Rust TA
**in-process** inside the target app. The app explicitly calls the API to generate
attested key pairs and certificate chains, which are:

- Signed by the same keybox format (`keybox.xml`)
- Structurally identical to real KeyMint attestations
- Internally consistent (same code-path as the reference TA)
- Carrying a locked/Verified root of trust

No system processes are modified, no permissions beyond what the app already has
are needed, and no root is required.

## Adding to your project

### 1. Build the library

```sh
cd TEESimulator
./gradlew :embeddable:build
```

The AAR is output at `embeddable/build/outputs/aar/embeddable-release.aar`.

### 2. Add the AAR to your app

Place the AAR in your app's `libs/` directory and add to `build.gradle.kts`:

```kotlin
dependencies {
    implementation(files("libs/embeddable-release.aar"))
}
```

### 3. Build the Rust TA

The C++ native library links against the Rust TA static library. Build it first:

```sh
cd TEESimulator/rust
ANDROID_NDK_HOME=/path/to/ndk bash build.sh
```

The build script will produce `rust/target/aarch64-linux-android/release/libteesim_km.a`.

## Quick Start

```kotlin
import org.matrix.teesim.embedded.TeeSimEmbedded

// 1. Load keybox.xml (must contain RSA + ECDSA keys with certificate chains)
//    Place your keybox in assets/ and load it at runtime.
val keyboxXml = assets.open("keybox.xml").bufferedReader().readText()

// 2. Initialize the TA with default config (locked/Verified TEE)
val ok = TeeSimEmbedded.initialize(keyboxXml.toByteArray())
if (!ok) { /* handle error */ }

// 3. Generate an attestation with a challenge from your server
val challenge = "server-nonce-123456".toByteArray(Charsets.UTF_8)
val result = TeeSimEmbedded.generateAttestation(challenge)

if (result != null) {
    // 4. Parse the certificate chain
    for (derCert in result.certificateChain) {
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(derCert.inputStream()) as X509Certificate
        println("Cert: ${cert.subjectX500Principal}")
    }
}

// 5. Clean up when done (e.g., in onDestroy())
TeeSimEmbedded.destroy()
```

## Advanced Configuration

For full control over the device identity and patch levels:

```kotlin
val config = TeeSimEmbedded.Config(
    securityLevel = 1,              // 1 = TrustedEnvironment
    osVersion = 160000,             // Android 16
    osPatchLevel = 202508,          // August 2025
    vendorPatchLevel = 20250805,    // August 5, 2025
    bootPatchLevel = 20250805,
    deviceLocked = true,
    verifiedBootState = 0,          // 0 = Verified
    attestVersionTee = 400,
    attestVersionStrongbox = 400,
    deviceIds = TeeSimEmbedded.DeviceIds(
        brand = "Google",
        device = "oriole",
        product = "pixel_6",
        manufacturer = "Google",
        model = "Pixel 6"
    )
)

TeeSimEmbedded.initialize(keyboxXml.toByteArray(), config)
```

## Patch Mode

If you already have a real hardware attestation leaf and want to re-sign it under
the keybox (preserving its public key and attestation content):

```kotlin
val patchedChain = TeeSimEmbedded.patchAttestation(realLeafDer)
// patchedChain[0] is the patched leaf, patchedChain[1..] is the keybox chain
```

## API Reference

### Initialization

| Method | Description |
|--------|-------------|
| `initialize(keyboxXml)` | Initialize with defaults |
| `initialize(keyboxXml, config)` | Initialize with full config |
| `destroy()` | Release TA resources |
| `isInitialized()` | Check if initialized |

### Attestation

| Method | Description |
|--------|-------------|
| `generateAttestation(challenge)` | Generate attested key pair |
| `patchAttestation(leafDer)` | Re-sign existing attestation |
| `isOurBlob(blob)` | Check if blob is from our TA |
| `deleteKey(keyBlob)` | Delete a key from TA |
| `verifyChain(certs)` | Verify keybox-signed chain |

## Requirements

- **Android 10+ (API 29+)**
- **arm64-v8a or x86_64** (the Rust TA only compiles for 64-bit)
- **A keybox.xml** with RSA + ECDSA keys and >= 2 certificate chain depth
- **No root required**

## Keybox Format

```xml
<?xml version="1.0"?>
<AndroidAttestation>
  <Keybox DeviceID="...">
    <Key algorithm="rsa">
      <PrivateKey format="pem">-----BEGIN PRIVATE KEY-----...</PrivateKey>
      <CertificateChain>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----...</Certificate>
        <!-- ... intermediate(s) and root ... -->
      </CertificateChain>
    </Key>
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----...</PrivateKey>
      <CertificateChain>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----...</Certificate>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
```

## Building from source

```sh
# 1. Build the Rust TA
cd TEESimulator/rust
export ANDROID_NDK_HOME=/path/to/android-ndk
bash build.sh

# 2. Build the AAR
cd ..
./gradlew :embeddable:build
# → embeddable/build/outputs/aar/embeddable-release.aar
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Target APK                          │
│  ┌───────────────────────────────────────────┐       │
│  │       TeeSimEmbedded (Kotlin API)          │       │
│  │  - initialize()                            │       │
│  │  - generateAttestation()                   │       │
│  │  - patchAttestation()                      │       │
│  │  - destroy()                               │       │
│  └──────────────┬────────────────────────────┘       │
│                 │ JNI                                │
│  ┌──────────────▼────────────────────────────┐       │
│  │   teesim_embedded_jni.cpp (C++ JNI bridge)│      │
│  │   - libteesim_embedded.so               │       │
│  └──────────────┬────────────────────────────┘       │
│                 │ C ABI (teesim_km.h)                │
│  ┌──────────────▼────────────────────────────┐       │
│  │   Rust TA (libteesim_km.a → linked in)    │       │
│  │   - KeyMint reference implementation      │       │
│  │   - Keybox-based attestation signing      │       │
│  │   - kmr-ta + BoringSSL                    │       │
│  └───────────────────────────────────────────┘       │
│                                                       │
│  BoringSSL symbols resolved at runtime from            │
│  system libcrypto.so (always loaded by Android)       │
└─────────────────────────────────────────────────────┘
```

## Comparison with the root-based module

| Feature | Root module (Magisk) | Embedded library |
|---------|---------------------|-----------------|
| System-wide interception | Yes | No |
| Requires root | Yes | **No** |
| App code changes | None | Must call API |
| Works with any app | Yes | Only the host APK |
| Artifact | Magisk module zip | AAR library |
| Dependencies | keystore2 injection | In-process only |

## License

GPL-3.0-or-later (same as the parent TEESimulator project)