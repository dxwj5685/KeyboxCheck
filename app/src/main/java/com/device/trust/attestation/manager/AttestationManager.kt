package com.device.trust.attestation.manager

import android.os.Build
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

            // 密钥生成配置，兼容API 26+
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setAttestationChallenge(CHALLENGE.toByteArray())
                setUserAuthenticationRequired(false)
                // 仅在API 31+ 强制TEE级别，低版本默认使用TEE生成密钥
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    setSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
                }
            }

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            ks.getCertificateChain(KEY_ALIAS)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
