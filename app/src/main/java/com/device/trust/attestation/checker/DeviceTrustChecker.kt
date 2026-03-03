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
        // 1. 生成Attestation证书链
        val certChain = attestManager.generateAttestationChain()
            ?: return TrustResult(
                isTrusted = false,
                riskType = RiskType.ATTESTATION_FAILED,
                message = "设备不支持Key Attestation，或Bootloader已解锁、系统被篡改"
            )

        val x509Chain = certChain.filterIsInstance<X509Certificate>().toTypedArray()
        val leafCert = x509Chain.firstOrNull() // 叶子证书，包含设备信息

        // 2. 核心安全校验：仅信任谷歌官方根证书签发的证书链
        if (!certValidator.validateCertificateChain(x509Chain)) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.ROOT_CA_INVALID,
                message = "证书链校验失败，非谷歌官方根证书签发，疑似非原厂设备"
            )
        }

        // 3. 提取证书链中所有的设备序列号
        val deviceSerialList = extensionParser.extractAllDeviceSerials(x509Chain)

        // 4. 你的核心规则：多个设备序列号，直接判定非原厂密钥
        if (deviceSerialList.size > 1) {
            return TrustResult(
                isTrusted = false,
                riskType = RiskType.MULTIPLE_SERIAL_NUMBER,
                message = "似乎是非原厂密钥",
                certificateSerial = deviceSerialList.joinToString(", ")
            )
        }

        // 5. 提取Bootloader状态（和vvb2060对齐）
        val isBootloaderLocked = leafCert?.let { extensionParser.isBootloaderLocked(it) }
        val deviceSerial = deviceSerialList.firstOrNull()

        // 6. 最终可信判定
        return when {
            // 有设备序列号，Bootloader锁定，完全可信
            !deviceSerial.isNullOrBlank() && isBootloaderLocked == true -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "✅ 设备可信，原厂密钥校验通过，Bootloader已锁定",
                    deviceSerial = deviceSerial
                )
            }
            // 有设备序列号，Bootloader解锁，降级可信
            !deviceSerial.isNullOrBlank() && isBootloaderLocked == false -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "⚠️ 设备可信，证书由谷歌官方根证书签发，Bootloader已解锁",
                    deviceSerial = deviceSerial
                )
            }
            // 无设备序列号，Bootloader锁定，正常可信
            deviceSerial.isNullOrBlank() && isBootloaderLocked == true -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "✅ 设备可信，证书由谷歌官方根证书签发，Bootloader已锁定，设备未写入序列号"
                )
            }
            // 无设备序列号，Bootloader解锁，降级可信
            else -> {
                TrustResult(
                    isTrusted = true,
                    riskType = RiskType.TRUSTED,
                    message = "⚠️ 设备可信，证书由谷歌官方根证书签发，Bootloader已解锁，设备未写入序列号"
                )
            }
        }
    }
}
