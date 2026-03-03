package com.device.trust.attestation.validator

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.X509Certificate

class AttestationExtensionParser {
    companion object {
        // Android Key Attestation 扩展OID
        private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"
        // 设备序列号对应的Keymaster Tag 713
        private const val TAG_ATTESTATION_ID_SERIAL = 713
    }

    // 从证书中提取所有序列号（对齐vvb2060项目的解析逻辑）
    fun extractAllSerials(certChain: Array<X509Certificate>): List<String> {
        val serials = mutableListOf<String>()
        certChain.forEach { cert ->
            extractSerialFromCert(cert)?.let { serial ->
                if (serial.isNotBlank()) {
                    serials.add(serial)
                }
            }
        }
        return serials
    }

    // 从单个证书中解析序列号
    private fun extractSerialFromCert(cert: X509Certificate): String? {
        return try {
            // 1. 提取Attestation扩展
            val extensionValue = cert.getExtensionValue(ATTESTATION_EXTENSION_OID) ?: return null

            // 2. 解析ASN.1结构，获取KeyDescription
            val asn1Input = ASN1InputStream(extensionValue)
            val octetString = asn1Input.readObject() as org.bouncycastle.asn1.DEROctetString
            val keyDescriptionSeq = ASN1InputStream(octetString.octets).readObject() as ASN1Sequence

            // 3. KeyDescription结构：第6个是softwareEnforced，第7个是teeEnforced
            // 优先从TEE中读取（安全硬件写入），其次从软件区读取
            val teeEnforced = keyDescriptionSeq.getObjectAt(7) as ASN1Sequence
            val softwareEnforced = keyDescriptionSeq.getObjectAt(6) as ASN1Sequence

            // 4. 从授权列表中提取Tag 713的序列号
            return extractSerialFromAuthList(teeEnforced) ?: extractSerialFromAuthList(softwareEnforced)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 从授权列表中解析序列号
    private fun extractSerialFromAuthList(authList: ASN1Sequence): String? {
        return try {
            authList.objects.forEach { obj ->
                val taggedObj = obj as ASN1TaggedObject
                // 匹配Tag 713（序列号）
                if (taggedObj.tagNo == TAG_ATTESTATION_ID_SERIAL) {
                    val octetString = taggedObj.baseObject as org.bouncycastle.asn1.DEROctetString
                    return String(octetString.octets)
                }
            }
            null
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
