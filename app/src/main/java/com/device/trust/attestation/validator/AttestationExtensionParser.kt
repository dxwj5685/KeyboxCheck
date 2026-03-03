package com.device.trust.attestation.validator

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.X509Certificate
import java.util.Enumeration

class AttestationExtensionParser {
    companion object {
        // Android Key Attestation 固定OID
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        // Keymaster 标准Tag定义（和vvb2060完全对齐）
        private const val TAG_ATTESTATION_ID_SERIAL = 713 // 设备序列号
        private const val TAG_BOOTLOADER_STATE = 709 // Bootloader锁定状态
        private const val INDEX_SOFTWARE_ENFORCED = 6
        private const val INDEX_TEE_ENFORCED = 7
    }

    // 解析证书链中所有的设备序列号（异常场景才会有多个）
    fun extractAllDeviceSerials(chain: Array<X509Certificate>): List<String> {
        val serials = mutableListOf<String>()
        chain.forEach { cert ->
            extractDeviceSerialFromCert(cert)?.takeIf { it.isNotBlank() }?.let {
                serials.add(it)
            }
        }
        return serials
    }

    // 提取Bootloader锁定状态
    fun isBootloaderLocked(cert: X509Certificate): Boolean? {
        return try {
            val extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID) ?: return null
            val octetString = ASN1OctetString.getInstance(extensionValue)
            val keyDescription = ASN1Sequence.getInstance(ASN1InputStream(octetString.octets).readObject())
            
            val teeEnforced = keyDescription.getObjectAt(INDEX_TEE_ENFORCED) as ASN1Sequence
            val softwareEnforced = keyDescription.getObjectAt(INDEX_SOFTWARE_ENFORCED) as ASN1Sequence

            // 优先从TEE读取Bootloader状态
            findBootloaderState(teeEnforced) ?: findBootloaderState(softwareEnforced)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 从单个证书中提取设备序列号
    private fun extractDeviceSerialFromCert(cert: X509Certificate): String? {
        return try {
            val extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID) ?: return null
            val octetString = ASN1OctetString.getInstance(extensionValue)
            val keyDescription = ASN1Sequence.getInstance(ASN1InputStream(octetString.octets).readObject())
            
            val teeEnforced = keyDescription.getObjectAt(INDEX_TEE_ENFORCED) as ASN1Sequence
            val softwareEnforced = keyDescription.getObjectAt(INDEX_SOFTWARE_ENFORCED) as ASN1Sequence

            findSerialInAuthList(teeEnforced) ?: findSerialInAuthList(softwareEnforced)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 从授权列表中查找设备序列号
    private fun findSerialInAuthList(authList: ASN1Sequence): String? {
        val objects: Enumeration<*> = authList.objects
        while (objects.hasMoreElements()) {
            val obj = objects.nextElement()
            if (obj !is ASN1TaggedObject) continue
            if (obj.tagNo == TAG_ATTESTATION_ID_SERIAL) {
                val serialOctet = ASN1OctetString.getInstance(obj.baseObject)
                return String(serialOctet.octets)
            }
        }
        return null
    }

    // 从授权列表中查找Bootloader状态
    private fun findBootloaderState(authList: ASN1Sequence): Boolean? {
        val objects: Enumeration<*> = authList.objects
        while (objects.hasMoreElements()) {
            val obj = objects.nextElement()
            if (obj !is ASN1TaggedObject) continue
            if (obj.tagNo == TAG_BOOTLOADER_STATE) {
                val value = ASN1OctetString.getInstance(obj.baseObject).octets
                // 0=解锁，1=锁定
                return value.isNotEmpty() && value[0] == 1.toByte()
            }
        }
        return null
    }
}
