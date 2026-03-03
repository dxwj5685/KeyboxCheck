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
            // 初始化KeyStore
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            // 清空历史密钥
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)

            // 密钥生成配置，全版本兼容
            val specBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setAttestationChallenge(CHALLENGE.toByteArray())
                setUserAuthenticationRequired(false)
                // 仅在API 31+ 强制TEE安全级别，低版本自动使用默认TEE生成
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    setSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
                }
            }

            // 生成密钥对
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())
            keyPairGenerator.generateKeyPair()

            // 返回完整证书链
            keyStore.getCertificateChain(KEY_ALIAS)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
