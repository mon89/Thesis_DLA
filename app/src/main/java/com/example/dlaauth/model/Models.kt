package com.example.dlaauth.model

import com.google.gson.annotations.SerializedName

// ---------------------------------------------------------------------------
// Passkey Registration
// ---------------------------------------------------------------------------

data class RegisterOptionsResponse(
    val userId: String,
    val options: PasskeyRegistrationOptions,
)

data class PasskeyRegistrationOptions(
    val challenge: String,
    val rp: RelyingParty,
    val user: UserEntity,
    @SerializedName("pubKeyCredParams")
    val pubKeyCredParams: List<PubKeyCredParam>,
    val authenticatorSelection: AuthenticatorSelection? = null,
    val timeout: Long? = null,
    val excludeCredentials: List<CredentialDescriptor>? = null,
)

data class RelyingParty(
    val id: String,
    val name: String,
)

data class UserEntity(
    val id: String,
    val name: String,
    val displayName: String,
)

data class PubKeyCredParam(
    val type: String,
    val alg: Int,
)

data class AuthenticatorSelection(
    val residentKey: String? = null,
    val userVerification: String? = null,
)

// ---------------------------------------------------------------------------
// Passkey Authentication
// ---------------------------------------------------------------------------

data class LoginOptionsResponse(
    val userId: String,
    val options: PasskeyAuthenticationOptions,
)

data class PasskeyAuthenticationOptions(
    val challenge: String,
    val rpId: String,
    val allowCredentials: List<CredentialDescriptor>? = null,
    val userVerification: String? = null,
    val timeout: Long? = null,
)

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

data class CredentialDescriptor(
    val id: String,
    val type: String = "public-key",
    val transports: List<String>? = null,
)

// ---------------------------------------------------------------------------
// Device Challenge
// ---------------------------------------------------------------------------

data class DeviceChallengeRequest(
    val dbkPublicKey: Map<String, String>
)

data class DeviceChallengeResponse(
    val challenge: String,
    val trustedDeviceCount: Int,
    val isBootstrap: Boolean,
)

// ---------------------------------------------------------------------------
// Device Verify
// ---------------------------------------------------------------------------

data class DeviceFinalizeRequest(
    val requestId: String,
    val loginAttemptId: String,
    val signature: String,
)

data class DeviceFinalizeResponse(
    val authComplete: Boolean,
    val deviceId: String? = null,
    val message: String? = null,
)

data class DeviceVerifyRequest(
    val signature: String,
    val signals: DeviceSignals,
    val clientMetrics: ClientMetrics? = null,
)

data class DeviceSignals(
    val userAgent: String,
    val platform: String = "Android",
    val timezone: String,
    val osVersion: String,
    val deviceModel: String,
    val timestamp: String,
    val ip: String? = null,
)

data class ClientMetrics(
    val dbkGenMs: Double,
    val dbkSignMs: Double,
    val totalMs: Double? = null,
    val hardware: String? = null,  // "STRONGBOX", "TEE", "SOFTWARE"
)

data class DeviceVerifyResponse(
    val flow: String,
    val status: String,
    val deviceId: String,
    val message: String? = null,
    val authComplete: Boolean,
    val approvalRequired: Boolean? = null,
    val requestId: String? = null,
    val loginAttemptId: String? = null,
)

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------

data class ApprovalRequestItem(
    val requestId: String,
    val requestingDeviceId: String,
    val loginAttemptId: String? = null,
    val requestContext: DeviceSignals? = null,
    val expiresAt: String? = null,
    val createdAt: String? = null,
)

data class ApprovalDecision(
    val requestId: String,
    val decision: String,
    val signature: String,
    val canonicalPayload: String,
)

// ---------------------------------------------------------------------------
// Device Status / List
// ---------------------------------------------------------------------------

data class ApprovalStatusResponse(
    val requestId: String,
    val deviceId: String,
    val approvalStatus: String,
    val deviceStatus: String,
    val expiresAt: String? = null,
)

data class DeviceListItem(
    val deviceId: String,
    val status: String,
    val createdAt: String? = null,
)

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

data class SessionInfo(
    val passkeyVerified: Boolean? = null,
    val authenticated: AuthenticatedSession? = null,
)

data class AuthenticatedSession(
    val username: String,
    val deviceId: String,
    val deviceStatus: String,
)

// ---------------------------------------------------------------------------
// Auth Flow Enum
// ---------------------------------------------------------------------------

enum class AuthFlow {
    BOOTSTRAP,
    TRUSTED_DEVICE,
    NEW_DEVICE,
    NEWLY_APPROVED,
    BLOCKED;

    companion object {
        fun fromString(s: String): AuthFlow = entries.firstOrNull {
            it.name.equals(s, ignoreCase = true)
        } ?: throw IllegalArgumentException("Unknown AuthFlow: $s")
    }
}
