/**
 * KeyStore helper for transparent attestation interception.
 *
 * This helper lets you keep using the standard Android KeyStore API for key
 * operations (sign/verify/encrypt/decrypt) while replacing the attestation
 * certificate chain with keybox-signed ones from the embedded TA.
 *
 * ## Basic Usage (Patch Mode)
 *
 * ```kotlin
 * // 1. Initialize TEESimulator with your keybox
 * TeeSimEmbedded.initialize(keyboxXml.toByteArray())
 *
 * // 2. Generate a real hardware key with attestation
 * val gen = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
 * gen.initialize(KeyGenParameterSpec.Builder("my-key", KeyProperties.PURPOSE_SIGN)
 *     .setDigests(KeyProperties.DIGEST_SHA256)
 *     .setAttestationChallenge(challenge)
 *     .build())
 * gen.generateKeyPair()
 *
 * // 3. Get the real chain and patch the leaf under the keybox
 * val patchedChain = TeeSimKeyStoreHelper.generatePatchedKey(
 *     alias = "my-key",
 *     challenge = challenge
 * ) // Returns the patched certificate chain
 * ```
 */
@file:Suppress("unused")

package org.matrix.teesim.embedded

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Helper for integrating TEESimulator attestation with the Android KeyStore.
 *
 * Provides convenience methods for the common "generate real key, patch
 * attestation" workflow.
 */
object TeeSimKeyStoreHelper {

    private const val TAG = "TeeSimKeyStore"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * Generate an attested key pair using AndroidKeyStore, then patch the
     * attestation chain using the embedded TA.
     *
     * This gives you a real AndroidKeyStore key (usable for signing/verification)
     * with a keybox-signed attestation chain.
     *
     * @param alias The keystore alias for the key
     * @param challenge The attestation challenge (nonce from server)
     * @param purposes Key purposes (default: SIGN + VERIFY)
     * @return The patched certificate chain as X509Certificate objects, or null
     */
    fun generatePatchedKey(
        alias: String,
        challenge: ByteArray,
        purposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ): List<X509Certificate>? {
        if (!TeeSimEmbedded.isInitialized()) {
            Log.e(TAG, "TEESimulator not initialized. Call TeeSimEmbedded.initialize() first.")
            return null
        }

        // 1. Generate the key in AndroidKeyStore
        try {
            val gen = java.security.KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )
            gen.initialize(
                KeyGenParameterSpec.Builder(alias, purposes)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(
                        java.security.spec.ECGenParameterSpec("secp256r1")
                    )
                    .setAttestationChallenge(challenge)
                    .build()
            )
            gen.generateKeyPair()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate key in AndroidKeyStore", e)
            return null
        }

        // 2. Get the real attestation chain from AndroidKeyStore
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val realChain = try {
            ks.getCertificateChain(alias)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get certificate chain", e)
            return null
        }

        if (realChain.isEmpty()) {
            Log.w(TAG, "Empty certificate chain for $alias")
            return null
        }

        // 3. Patch the leaf (first certificate) under the keybox
        val leafDer = (realChain[0] as X509Certificate).encoded
        val patchedDerChain = TeeSimEmbedded.patchAttestation(leafDer)
            ?: run {
                Log.w(TAG, "patchAttestation failed for $alias")
                return null
            }

        // 4. Parse back to X509Certificate objects
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            patchedDerChain.map { der ->
                cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse patched certificate chain", e)
            null
        }
    }

    /**
     * Generate a fully simulated key pair in the TA and return both the
     * key blob and certificate chain.
     *
     * **Note**: The resulting key is NOT usable with AndroidKeyStore APIs for
     * signing. Use this only when you need the complete attestation chain
     * and handle signing through other means.
     *
     * @param challenge The attestation challenge
     * @return AttestationResult containing the key blob and certificate chain
     */
    fun generateSimulatedAttestation(
        challenge: ByteArray
    ): TeeSimEmbedded.AttestationResult? {
        if (!TeeSimEmbedded.isInitialized()) {
            Log.e(TAG, "TEESimulator not initialized")
            return null
        }
        return TeeSimEmbedded.generateAttestation(challenge)
    }

    /**
     * Convenience: get the patched certificate chain for an already-generated
     * AndroidKeyStore key at [alias].
     *
     * Use this when you generated a key earlier and want to patch its
     * attestation now.
     */
    fun patchExistingKey(alias: String): List<X509Certificate>? {
        if (!TeeSimEmbedded.isInitialized()) {
            Log.e(TAG, "TEESimulator not initialized")
            return null
        }

        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val realChain = try {
            ks.getCertificateChain(alias)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get certificate chain", e)
            return null
        }

        if (realChain.isEmpty()) {
            Log.w(TAG, "Empty certificate chain for $alias")
            return null
        }

        val leafDer = (realChain[0] as X509Certificate).encoded
        val patchedDerChain = TeeSimEmbedded.patchAttestation(leafDer)
            ?: run {
                Log.w(TAG, "patchAttestation failed for $alias")
                return null
            }

        return try {
            val cf = CertificateFactory.getInstance("X.509")
            patchedDerChain.map { der ->
                cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse patched certificate chain", e)
            null
        }
    }
}