package com.device.trust.attestation.checker

import com.device.trust.attestation.manager.AttestationManager
import com.device.trust.attestation.model.RiskType
import com.device.trust.attestation.model.TrustResult
import com.device.trust.attestation.validator.AttestationExtensionParser
import com.device.trust.attestation.validator.CertificateValidator
import java.security.cert.X509Certificate

class DeviceTrustChecker {
    private val attestManager = AttestationManager()
    private val certValidator = CertificateValidator()
    private val extensionParser = AttestationExtensionParser()

    fun checkDeviceTrust(): TrustResult {
        // 1. 生成Attestation证书链（和原项目流程一致）
        val certChain = attestManager.generateAttestationChain()
            ?: return TrustResult(
                isTrusted = false,
                riskType = RiskType.ATTESTATION_FAILED,
                message = "设备不支持Key Attestation，或Bootloader已解锁、系统被篡改"
            )

        val x509Chain = certChain.filterIsInstance<X509Certificate>().toTypedArray()

        // 2. 证书链校验（核心安全校验，和原项目一致）
        if (!certValidator.validateCertificateChain(x509Chain)) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.ROOT_CA_INVALID,
                message = "证书链校验失败，非谷歌官方根证书签发，疑似非原厂设备"
            )
        }

        // 3. 提取证书链中的所有序列号
        val serialList = extensionParser.extractAllSerials(x509Chain)

        // 4. 你的核心规则：多序列号直接判定非原厂密钥
        if (serialList.size > 1) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.MULTIPLE_SERIAL_NUMBER,
                message = "似乎是非原厂密钥",
                certificateSerial = serialList.joinToString(", ")
            )
        }

        // 5. 最终可信判定（和原项目逻辑对齐）
        val certSerial = serialList.firstOrNull()
        return when {
            !certSerial.isNullOrBlank() -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "✅ 设备可信，原厂密钥校验通过",
                    certificateSerial = certSerial
                )
            }
            else -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "⚠️ 设备可信，证书由谷歌官方根证书签发。设备未写入序列号（Bootloader已解锁或设备不支持ID Attestation）"
                )
            }
        }
    }
}
