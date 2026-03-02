package com.keyboxchecker.demo

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.AttestationUtils
import com.google.android.attestation.CertificateParser
import com.google.android.attestation.RootOfTrust
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * 原厂Keybox核心校验器
 * 专门识别：Tricky Store + 早期设备漏洞提取Keybox
 */
object KeyboxSecurityValidator {
    // Google硬件认证根证书（SHA-256指纹，固定值，不可伪造）
    private const val GOOGLE_HW_ROOT_FINGERPRINT = "38:DA:6B:51:54:91:69:84:74:4F:71:70:50:25:9E:8F:4F:1D:49:E6:3A:6D:6B:0F:8F:1A:22:8A:4A:8B:9C:0D"

    // 校验结果数据类（用于UI展示）
    data class CheckResult(
        val isFactoryKeybox: Boolean, // 是否原厂
        val log: List<String> // 详细校验日志
    )

    /**
     * 执行完整校验
     * @param deviceSerial 本机真实Serial（需权限获取）
     */
    fun checkFactoryKeybox(deviceSerial: String): CheckResult {
        val log = mutableListOf<String>()
        var isPass = true

        try {
            // 步骤1：生成硬件绑定的临时密钥，获取认证证书链
            log.add("【1/6】生成硬件认证密钥...")
            val keyEntry = generateAttestationKey()
            val certChain = keyEntry.certificateChain as Array<X509Certificate>
            if (certChain.isEmpty()) {
                log.add("❌ 证书链为空：非硬件级密钥")
                isPass = false
                return CheckResult(false, log)
            }
            log.add("✅ 成功获取硬件证书链（长度：${certChain.size}）")

            // 步骤2：解析Google认证数据
            log.add("\n【2/6】解析硬件认证数据...")
            val attestation = CertificateParser.parseAttestation(certChain[0])
            log.add("✅ 认证数据解析完成：安全级别=${attestation.keymasterSecurityLevel.name}")

            // 步骤3：校验硬件安全级别（拒绝软件模拟）
            log.add("\n【3/6】校验硬件安全级别...")
            val isHardware = attestation.keymasterSecurityLevel.isHardware
            if (!isHardware) {
                log.add("❌ 安全级别非硬件：可能是软件模拟Keybox")
                isPass = false
            } else {
                log.add("✅ 安全级别为硬件（STRONGBOX/TEE）")
            }

            // 步骤4：校验Google根证书（拒绝自签伪造链）
            log.add("\n【4/6】校验Google硬件根证书...")
            val rootCert = certChain.last()
            val rootFingerprint = AttestationUtils.getCertificateFingerprint(rootCert)
                .replace(":", "")
                .uppercase()
            val targetFingerprint = GOOGLE_HW_ROOT_FINGERPRINT.replace(":", "")
                .uppercase()
            if (rootFingerprint != targetFingerprint) {
                log.add("❌ 根证书不匹配：实际=$rootFingerprint，预期=$targetFingerprint")
                isPass = false
            } else {
                log.add("✅ 根证书为Google官方硬件认证根")
            }

            // 步骤5：校验信任根（核心：识别提取Keybox的关键）
            log.add("\n【5/6】校验硬件信任根（verifiedBootKey）...")
            val rootOfTrust = attestation.rootOfTrust
            // 校验设备锁定状态
            if (!rootOfTrust.deviceLocked) {
                log.add("⚠️ 设备未锁定：Bootloader可能未锁")
            }
            // 校验启动链状态
            if (rootOfTrust.verifiedBootState != RootOfTrust.VerifiedBootState.VERIFIED) {
                log.add("❌ 启动链未验证：系统可能被篡改")
                isPass = false
            }
            // 核心：对比verifiedBootKey（提取Keybox必败）
            val localVbKey = getLocalVerifiedBootKey()
            val certVbKey = Base64.encodeToString(rootOfTrust.verifiedBootKey, Base64.NO_WRAP)
            if (localVbKey.isBlank()) {
                log.add("⚠️ 无法获取本机verifiedBootKey：设备适配问题")
            } else if (localVbKey != certVbKey) {
                log.add("❌ verifiedBootKey不匹配：证书中为旧设备哈希（提取Keybox特征）")
                isPass = false
            } else {
                log.add("✅ verifiedBootKey与本机硬件完全一致")
            }

            // 步骤6：校验Serial绑定（提取Keybox会出现多Serial/不匹配）
            log.add("\n【6/6】校验设备Serial绑定...")
            val certSerial = attestation.serialNumber ?: "未知"
            if (certSerial != deviceSerial) {
                log.add("❌ Serial不匹配：证书=$certSerial，本机=$deviceSerial")
                isPass = false
            } else {
                log.add("✅ 证书Serial与本机完全一致")
            }

        } catch (e: Exception) {
            log.add("\n❌ 校验过程异常：${e.message}（风险设备特征）")
            isPass = false
        }

        val finalLog = mutableListOf<String>()
        finalLog.add("检测结果：${if (isPass) "✅ 原厂密钥（安全设备）" else "❌ 非原厂密钥（风险设备：Tricky Store+提取Keybox）"}")
        finalLog.addAll(log)
        return CheckResult(isPass, finalLog)
    }

    /**
     * 生成带硬件认证的EC密钥对
     */
    private fun generateAttestationKey(): KeyStore.PrivateKeyEntry {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "factory_check_${System.currentTimeMillis()}"

        // 先删除旧密钥（避免缓存干扰）
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }

   