package com.device.trust.attestation.model
data class TrustResult(
    val isTrusted: Boolean,
    val riskType: RiskType,
    val message: String,
    val deviceSerial: String? = null,
    val certificateSerial: String? = null
)
