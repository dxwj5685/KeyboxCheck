package com.device.trust.attestation.checker

import com.device.trust.attestation.manager.AttestationManager
import com.device.trust.attestation.model.RiskType
import com.device.trust.attestation.model.TrustResult
import com.device.trust.attestation.validator.AttestationExtensionParser
import com.device.trust.attestation.validator.CertificateValidator
import java.security.cert.X509Certificate

class DeviceTrustChecker {
    private val attest = AttestationManager()
    private val certValidator = CertificateValidator()
    private val parser = AttestationExtensionParser()

    fun check(): TrustResult {
        // 1. 获取硬件密钥证书链
        val chain = attest.getAttestationCertificateChain()
            ?: return TrustResult(
                isTrusted = false,
                riskType = RiskType.ATTESTATION_FAILED,
                message = "获取证书链失败，设备不支持TEE硬件密钥证明"
            )

        val x509Chain = chain.filterIsInstance<X509Certificate>().toTypedArray()

        // 2. 核心校验：仅信任谷歌官方根证书签发的证书链（这一步是核心，只要通过就说明是原厂密钥）
        if (!certValidator.validate(x509Chain)) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.ROOT_CA_INVALID,
                message = "证书链校验失败，非谷歌官方根证书或AOSP公开测试密钥"
            )
        }

        // 3. 从证书链中提取所有SERIALNUMBER
        val certSerials = parser.extractAllSerials(x509Chain)

        // 4. 核心规则：多SERIALNUMBER直接判定非原厂密钥
        if (certSerials.size > 1) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.MULTIPLE_SERIAL_NUMBER,
                message = "似乎是非原厂密钥",
                certificateSerial = certSerials.joinToString(", ")
            )
        }

        // 5. 序列号校验逻辑优化，区分不同场景，避免误判
        val certSerial = certSerials.firstOrNull()
        return when {
            // 证书有绑定序列号，校验通过
            !certSerial.isNullOrBlank() -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "设备可信，原厂密钥校验通过",
                    certificateSerial = certSerial
                )
            }
            // 证书无序列号，但是证书链合法，说明是Bootloader解锁/设备不支持ID Attestation
            else -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "设备可信，证书由谷歌官方根证书签发。设备未写入序列号（Bootloader已解锁或设备不支持ID Attestation）"
                )
            }
        }
    }
}
