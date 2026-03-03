package com.device.trust.attestation.manager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec

class AttestationManager {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "DeviceTrustKey"
        private const val CHALLENGE = "DeviceTrust_2026"
    }

    fun getAttestationCertificateChain(): Array<Certificate>? {
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)

            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setAttestationChallenge(CHALLENGE.toByteArray())
                setSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
                setUserAuthenticationRequired(false)
            }.build()

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            kpg.initialize(spec)
            kpg.generateKeyPair()
            ks.getCertificateChain(KEY_ALIAS)
        } catch (e: Exception) {
            null
        }
    }
}
