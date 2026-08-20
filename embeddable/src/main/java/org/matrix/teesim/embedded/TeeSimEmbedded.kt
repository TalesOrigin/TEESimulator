/**
 * TEESimulator Embedded — attestation library for Android APKs.
 *
 * This class wraps the Rust KeyMint TA (Trusted Application) and provides
 * keybox-signed attestation certificate generation **within the app's own
 * process**. No root access is required.
 *
 * ## Usage
 *
 * ```kotlin
 * // 1. Load the keybox XML (must contain RSA + ECDSA keys with chains)
 * val keyboxXml = assetManager.open("keybox.xml").bufferedReader().readText()
 *
 * // 2. Initialize the TA
 * TeeSimEmbedded.initialize(keyboxXml.toByteArray())
 *
 * // 3. Generate attestation certificate chain
 * val challenge = "my-attestation-challenge".toByteArray()
 * val certChain = TeeSimEmbedded.generateAttestation(challenge)
 *
 * // 4. Use the cert chain (e.g., send to server)
 * for (cert in certChain) {
 *     val x509 = CertificateFactory.getInstance("X.509")
 *         .generateCertificate(cert.inputStream()) as X509Certificate
 * }
 *
 * // 5. Clean up when done
 * TeeSimEmbedded.destroy()
 * ```
 *
 * The certificate chain is signed by the keybox and carries a locked/Verified
 * root of trust, just like the original TEESimulator module.
 */
package org.matrix.teesim.embedded

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Embedded TEESimulator: hardware-backed attestation simulation without root.
 *
 * Singleton that manages the in-process KeyMint TA lifetime.
 */
object TeeSimEmbedded {

    private var initialized = false

    // JNI native methods
    private external fun nativeInitSimple(keyboxXml: ByteArray): Boolean

    private external fun nativeInit(
        keyboxXml: ByteArray,
        securityLevel: Int,
        osVersion: Int,
        osPatchLevel: Int,
        vendorPatchLevel: Int,
        bootPatchLevel: Int,
        vbKey: ByteArray?,
        vbHash: ByteArray?,
        deviceLocked: Boolean,
        verifiedBootState: Int,
        attestVersionTee: Int,
        attestVersionStrongbox: Int,
        deviceIds: DeviceIds?
    ): Boolean

    private external fun nativeGenerateAttestation(
        challenge: ByteArray?
    ): Array<ByteArray>?

    private external fun nativePatchAttestation(leafDer: ByteArray): Array<ByteArray>?

    private external fun nativeIsMarked(blob: ByteArray): Boolean

    private external fun nativeDeleteKey(keyBlob: ByteArray): Int

    private external fun nativeDestroy()

    private external fun nativeIsInitialized(): Boolean

    init {
        System.loadLibrary("teesim_embedded")
    }

    /**
     * Device identity values to embed in attestation records.
     * All fields are optional — empty/null means "decline that field".
     */
    data class DeviceIds(
        val brand: String = "",
        val device: String = "",
        val product: String = "",
        val serial: String = "",
        val imei: String = "",
        val imei2: String = "",
        val meid: String = "",
        val manufacturer: String = "",
        val model: String = ""
    )

    /**
     * Full TA configuration.
     */
    data class Config(
        /** 0=Software, 1=TrustedEnvironment (default), 2=StrongBox */
        val securityLevel: Int = 1,
        /** OS version: major*10000 + minor*100 + sub. Default: 160000 (Android 16) */
        val osVersion: Int = 160000,
        /** System patch level: YYYYMM */
        val osPatchLevel: Int = 202508,
        /** Vendor patch level: YYYYMMDD */
        val vendorPatchLevel: Int = 20250805,
        /** Boot patch level: YYYYMMDD */
        val bootPatchLevel: Int = 20250805,
        /** Verified boot key (32 bytes). Null to use a device-consistent default */
        val verifiedBootKey: ByteArray? = null,
        /** Verified boot hash (32 bytes). Null to use a device-consistent default */
        val verifiedBootHash: ByteArray? = null,
        /** Device locked state. Default: true */
        val deviceLocked: Boolean = true,
        /** 0=Verified, 1=SelfSigned, 2=Unverified, 3=Failed. Default: 0 */
        val verifiedBootState: Int = 0,
        /** KeyMint HAL attestation version at TEE */
        val attestVersionTee: Int = 400,
        /** KeyMint HAL attestation version at StrongBox */
        val attestVersionStrongbox: Int = 400,
        /** Device identity values (optional — null to decline ID attestation) */
        val deviceIds: DeviceIds? = null
    )

    /**
     * Result of an attestation key generation.
     */
    data class AttestationResult(
        /** DER-encoded certificate chain [leaf, intermediates..., root] */
        val certificateChain: List<ByteArray>,
        /** Key blob (opaque, needed for signing operations) */
        val keyBlob: ByteArray? = null
    )

    /**
     * Initialize the TA with a keybox XML and default configuration.
     *
     * @param keyboxXml The raw bytes of a keybox.xml file containing RSA + ECDSA
     *                  keys and certificate chains
     * @return true if initialization succeeded, false otherwise
     */
    fun initialize(keyboxXml: ByteArray): Boolean {
        val ok = nativeInitSimple(keyboxXml)
        initialized = ok
        return ok
    }

    /**
     * Initialize the TA with a keybox XML and full configuration.
     *
     * @param keyboxXml The raw bytes of a keybox.xml file
     * @param config Full TA configuration
     * @return true if initialization succeeded, false otherwise
     */
    fun initialize(keyboxXml: ByteArray, config: Config): Boolean {
        val ids = config.deviceIds
        val ok = nativeInit(
            keyboxXml,
            config.securityLevel,
            config.osVersion,
            config.osPatchLevel,
            config.vendorPatchLevel,
            config.bootPatchLevel,
            config.verifiedBootKey,
            config.verifiedBootHash,
            config.deviceLocked,
            config.verifiedBootState,
            config.attestVersionTee,
            config.attestVersionStrongbox,
            ids
        )
        initialized = ok
        return ok
    }

    /**
     * Generate a key pair with attestation certificate chain.
     *
     * The key is generated entirely in the in-process TA with the profile's
     * keybox. The returned certificate chain is a valid KeyMint attestation
     * chain signed by the keybox, carrying the configured root of trust.
     *
     * @param challenge The attestation challenge (arbitrary bytes, typically a
     *                  nonce from a server). May be null for no challenge.
     * @return AttestationResult containing the certificate chain, or null on failure
     */
    fun generateAttestation(challenge: ByteArray? = null): AttestationResult? {
        checkInitialized()
        val certs = nativeGenerateAttestation(challenge)
            ?: return null
        return AttestationResult(
            certificateChain = certs.toList()
        )
    }

    /**
     * Re-sign an existing real hardware attestation leaf under the keybox.
     *
     * This is "patch mode": the real leaf's public key and attestation content
     * are preserved, but the chain is re-rooted at the keybox with a locked/
     * Verified root of trust.
     *
     * @param leafDer The DER-encoded attestation certificate leaf from the real
     *                hardware KeyMint
     * @return The re-signed certificate chain [patched leaf, keybox chain...],
     *         or null on failure
     */
    fun patchAttestation(leafDer: ByteArray): List<ByteArray>? {
        checkInitialized()
        return nativePatchAttestation(leafDer)?.toList()
    }

    /**
     * Check whether a key blob was created by this TA.
     */
    fun isOurBlob(blob: ByteArray): Boolean {
        if (!initialized) return false
        return nativeIsMarked(blob)
    }

    /**
     * Delete a key from the TA's internal storage.
     * @return 0 on success, negative KeyMint error code on failure
     */
    fun deleteKey(keyBlob: ByteArray): Int {
        checkInitialized()
        return nativeDeleteKey(keyBlob)
    }

    /**
     * Check whether the TA has been initialized.
     */
    fun isInitialized(): Boolean {
        initialized = nativeIsInitialized()
        return initialized
    }

    /**
     * Destroy the TA and release all resources.
     *
     * After calling this, initialize() must be called again before any
     * other operations.
     */
    fun destroy() {
        if (initialized) {
            nativeDestroy()
            initialized = false
        }
    }

    /**
     * Verify that an X509 certificate chain was signed by the keybox.
     * This is useful for testing/debugging attestation verification.
     *
     * @param certChain The DER-encoded certificate chain [leaf, ...]
     * @return true if the chain verifies under the keybox root
     */
    fun verifyChain(certChain: List<ByteArray>): Boolean {
        if (certChain.size < 2) return false
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val certs = certChain.map { cf.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }

            // Verify each certificate is signed by the next one
            for (i in 0 until certs.size - 1) {
                try {
                    certs[i].verify(certs[i + 1].publicKey)
                } catch (_: Exception) {
                    return false
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun checkInitialized() {
        if (!initialized) {
            throw IllegalStateException(
                "TEESimulator not initialized. Call TeeSimEmbedded.initialize() first."
            )
        }
    }
}