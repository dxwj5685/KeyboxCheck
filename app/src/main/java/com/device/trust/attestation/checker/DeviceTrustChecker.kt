package com.device.trust.attestation.checker

import android.content.Context
import android.os.Build
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
                false,
                RiskType.ATTESTATION_FAILED,
                "获取证书链失败，设备不支持TEE硬件密钥证明"
            )

        val x509Chain = chain.filterIsInstance<X509Certificate>().toTypedArray()

        // 2. 校验证书链（和CertificateValidator里的方法名完全匹配）
        if (!certValidator.validate(x509Chain)) {
            return TrustResult(
                false,
                RiskType.ROOT_CA_INVALID,
                "证书链校验失败，非谷歌官方根证书或AOSP测试密钥"
            )
        }

        // 3. 提取证书链所有序列号
        val certSerials = parser.extractAllSerials(x509Chain)

        // 4. 校验多序列号（非法移植/伪造）
        if (certSerials.size > 1) {
            return TrustResult(
                false,
                RiskType.MULTIPLE_SERIAL_NUMBER,
                "证书链存在多个无关序列号，疑似伪造或移植密钥",
                certificateSerial = certSerials.joinToString(", ")
            )
        }

        // 5. 获取设备真实序列号
        val deviceSerial = try {
            Build.getSerial()
        } catch (e: SecurityException) {
            return TrustResult(
                false,
                RiskType.PERMISSION_DENIED,
                "无读取设备序列号权限，无法完成校验"
            )
        }

        // 6. 校验序列号匹配性
        val certSerial = certSerials.firstOrNull()
        if (certSerial.isNullOrEmpty()) {
            return TrustResult(
                false,
                RiskType.SERIAL_NUMBER_MISMATCH,
                "证书未绑定设备序列号，疑似伪造证书",
                deviceSerial = deviceSerial
            )
        }

        return if (certSerial == deviceSerial) {
            TrustResult(
                true,
                RiskType.TRUSTED,
                "设备可信，证书由谷歌官方根证书签发，序列号匹配",
                deviceSerial = deviceSerial,
                certificateSerial = certSerial
            )
        } else {
            TrustResult(
                false,
                RiskType.SERIAL_NUMBER_MISMATCH,
                "证书序列号与设备真实序列号不匹配，疑似移植其他设备密钥",
                deviceSerial = deviceSerial,
                certificateSerial = certSerial
            )
        }
    }
}
