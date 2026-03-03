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
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "KeyAttestationKey"
        private const val CHALLENGE = "KeyAttestation"
    }

    fun generateAttestationChain(): Array<Certificate>? {
        return try {
            // 清空历史密钥
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }

            // 【对齐原项目】EC secp256r1 算法，安卓Key Attestation标准配置
            val keyGenSpecBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setAttestationChallenge(CHALLENGE.toByteArray())
                setUserAuthenticationRequired(false)
                // Android 11+ 开启设备属性Attestation，和原项目一致
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setDevicePropertiesAttestationIncluded(true)
                }
            }

            // 生成密钥对
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )
            keyPairGenerator.initialize(keyGenSpecBuilder.build())
            keyPairGenerator.generateKeyPair()

            // 返回完整证书链
            keyStore.getCertificateChain(KEY_ALIAS)
        } catch (e: Exception) {
            // 开启设备属性失败，降级生成（和原项目降级逻辑一致）
            generateFallbackChain()
        }
    }

    // 降级方案：不开启设备属性，保证生成成功
    private fun generateFallbackChain(): Array<Certificate>? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }

            val keyGenSpecBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setAttestationChallenge(CHALLENGE.toByteArray())
                setUserAuthenticationRequired(false)
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )
            keyPairGenerator.initialize(keyGenSpecBuilder.build())
            keyPairGenerator.generateKeyPair()

            keyStore.getCertificateChain(KEY_ALIAS)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
