package com.device.trust.attestation.validator

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import java.security.cert.X509Certificate

class AttestationExtensionParser {
    companion object {
        // Android Key Attestation 固定扩展OID
        private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"
        // 设备序列号对应的Keymaster固定Tag 713
        private const val TAG_ATTESTATION_ID_SERIAL = 713
    }

    // 从证书链中提取所有序列号
    fun extractAllSerials(certChain: Array<X509Certificate>): List<String> {
        val serials = mutableListOf<String>()
        certChain.forEach { cert: X509Certificate ->
            val serial = extractSerialFromCert(cert)
            if (serial != null && serial.isNotBlank()) {
                serials.add(serial)
            }
        }
        return serials
    }

    // 从单个证书中解析序列号
    private fun extractSerialFromCert(cert: X509Certificate): String? {
        return try {
            // 1. 提取Attestation扩展字段
            val extensionValue = cert.getExtensionValue(ATTESTATION_EXTENSION_OID)
                ?: return null

            // 2. 解析ASN.1结构，获取KeyDescription根序列
            val asn1Input = ASN1InputStream(extensionValue)
            val octetString = asn1Input.readObject() as ASN1OctetString
            val keyDescriptionSeq = ASN1InputStream(octetString.octets).readObject() as ASN1Sequence

            // 3. KeyDescription结构：
            // 索引6：softwareEnforced（软件层授权列表）
            // 索引7：teeEnforced（TEE安全硬件强制授权列表）
            val teeEnforced = keyDescriptionSeq.getObjectAt(7) as ASN1Sequence
            val softwareEnforced = keyDescriptionSeq.getObjectAt(6) as ASN1Sequence

            // 4. 优先从TEE中读取序列号，其次从软件区读取
            extractSerialFromAuthList(teeEnforced) ?: extractSerialFromAuthList(softwareEnforced)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 从授权列表中解析Tag 713对应的序列号
    private fun extractSerialFromAuthList(authList: ASN1Sequence): String? {
        return try {
            // 修复1：显式指定参数类型，解决类型推断错误
            val objects = authList.objects
            // 修复2：用for循环替代forEach，解决lambda内return的语法错误
            for (obj: ASN1Encodable in objects) {
                val taggedObj = obj as ASN1TaggedObject
                // 匹配序列号对应的Tag 713
                if (taggedObj.tagNo == TAG_ATTESTATION_ID_SERIAL) {
                    val octetString = taggedObj.baseObject as DEROctetString
                    return String(octetString.octets)
                }
            }
            // 没有找到对应Tag，返回null
            null
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
