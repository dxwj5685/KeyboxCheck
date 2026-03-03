package com.device.trust.attestation.checker
import android.content.Context
import android.os.Build
import com.device.trust.attestation.manager.AttestationManager
import com.device.trust.attestation.model.RiskType
import com.device.trust.attestation.model.TrustResult
import com.device.trust.attestation.validator.AttestationExtensionParser
import com.device.trust.attestation.validator.CertificateValidator
import java.security.cert.X509Certificate

class DeviceTrustChecker(private val ctx: Context) {
    private val attest = AttestationManager()
    private val certValidator = CertificateValidator()
    private val parser = AttestationExtensionParser()

    fun check(): TrustResult {
        val chain = attest.getAttestationCertificateChain()
            ?: return TrustResult(false, RiskType.ATTESTATION_FAILED, "获取证书链失败")

        val x509 = chain.filterIsInstance<X509Certificate>().toTypedArray()
        if (!certValidator.validate(x509)) {
            return TrustResult(false, RiskType.ROOT_CA_INVALID, "非谷歌官方证书或AOSP测试证书")
        }

        val serials = parser.extractAllSerials(x509)
        if (serials.size > 1) {
            return TrustResult(false, RiskType.MULTIPLE_SERIAL_NUMBER, "多个序列号：${serials}")
        }

        val deviceSerial = try {
            Build.getSerial()
        } catch (e: SecurityException) {
            return TrustResult(false, RiskType.PERMISSION_DENIED, "无读取序列号权限")
        }

        val certSerial = serials.firstOrNull()
        if (certSerial.isNullOrEmpty()) {
            return TrustResult(false, RiskType.SERIAL_NUMBER_MISMATCH, "证书无序列号")
        }

        return if (certSerial == deviceSerial) {
            TrustResult(true, RiskType.TRUSTED, "设备可信", deviceSerial, certSerial)
        } else {
            TrustResult(false, RiskType.SERIAL_NUMBER_MISMATCH, "序列号不匹配", deviceSerial, certSerial)
        }
    }
}
