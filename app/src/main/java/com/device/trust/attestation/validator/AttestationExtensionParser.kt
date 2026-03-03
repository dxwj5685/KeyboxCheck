package com.device.trust.attestation.validator
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import java.security.cert.X509Certificate

class AttestationExtensionParser {
    companion object {
        private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        private const val TAG_SERIAL = 704
    }

    fun extractSerial(cert: X509Certificate): String? {
        return try {
            val ext = cert.getExtensionValue(ATTESTATION_OID) ?: return null
            val octets = ASN1OctetString.getInstance(ext).octets
            val seq = ASN1Sequence.getInstance(ASN1InputStream(octets).readObject())
            val tee = seq.getObjectAt(5) as ASN1Sequence
            tee.forEach { entry ->
                val eSeq = ASN1Sequence.getInstance(entry)
                val tag = ASN1Integer.getInstance(eSeq.getObjectAt(0)).value.toInt()
                if (tag == TAG_SERIAL) {
                    val data = ASN1OctetString.getInstance(eSeq.getObjectAt(1)).octets
                    return String(data)
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    fun extractAllSerials(chain: Array<X509Certificate>): List<String> {
        return chain.mapNotNull { extractSerial(it) }
    }
}
