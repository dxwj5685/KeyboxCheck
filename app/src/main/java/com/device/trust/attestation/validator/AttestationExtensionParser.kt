package com.device.trust.attestation.validator

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.X509Certificate
import java.util.Enumeration

class AttestationExtensionParser {
    companion object {
        // 【对齐原项目】Android Key Attestation 固定OID
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        // 【对齐原项目】Keymaster 标准Tag定义
        private const val TAG_ATTESTATION_ID_SERIAL = 713
        // KeyDescription 结构索引（和AOSP、原项目完全一致）
        private const val INDEX_SOFTWARE_ENFORCED = 6
        private const val INDEX_TEE_ENFORCED = 7
    }

    // 从证书链中提取所有序列号
    fun extractAllSerials(chain: Array<X509Certificate>): List<String> {
        val serials = mutableListOf<String>()
        chain.forEach { cert ->
            extractSerialFromCert(cert)?.takeIf { it.isNotBlank() }?.let {
                serials.add(it)
            }
        }
        return serials
    }

    // 【对齐原项目】从单个证书解析序列号
    private fun extractSerialFromCert(cert: X509Certificate): String? {
        return try {
            // 1. 提取Attestation扩展
            val extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID) ?: return null
            // 2. 解析ASN.1结构，和原项目完全一致
            val octetString = ASN1OctetString.getInstance(extensionValue)
            val keyDescription = ASN1Sequence.getInstance(ASN1InputStream(octetString.octets).readObject())
            // 3. 优先从TEE强制区读取，其次从软件区读取（和原项目逻辑一致）
            val teeEnforced = keyDescription.getObjectAt(INDEX_TEE_ENFORCED) as ASN1Sequence
            val softwareEnforced = keyDescription.getObjectAt(INDEX_SOFTWARE_ENFORCED) as ASN1Sequence

            findSerialInAuthorizationList(teeEnforced) ?: findSerialInAuthorizationList(softwareEnforced)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 【对齐原项目】从授权列表中查找序列号Tag
    private fun findSerialInAuthorizationList(authList: ASN1Sequence): String? {
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
}
