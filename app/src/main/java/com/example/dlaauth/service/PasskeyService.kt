package com.example.dlaauth.service

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialRequest
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialCustomException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCustomException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.GetPublicKeyCredentialOption
import com.example.dlaauth.model.PasskeyAuthenticationOptions
import com.example.dlaauth.model.PasskeyRegistrationOptions
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject

class PasskeyService(private val context: Context) {

    private val TAG = "PasskeyService"
    private val credentialManager = CredentialManager.create(context)
    private val gson = Gson()

    suspend fun register(options: PasskeyRegistrationOptions): String {
        val excludeCredentials = JsonArray().apply {
            options.excludeCredentials?.forEach { cred ->
                add(JsonObject().apply {
                    addProperty("id", cred.id)
                    addProperty("type", cred.type)
                })
            }
        }

        val requestJson = JsonObject().apply {
            addProperty("challenge", options.challenge)
            add("rp", JsonObject().apply {
                addProperty("name", options.rp.name)
                addProperty("id", options.rp.id)
            })
            add("user", JsonObject().apply {
                addProperty("id", options.user.id)
                addProperty("name", options.user.name)
                addProperty("displayName", options.user.displayName)
            })
            add("pubKeyCredParams", JsonArray().apply {
                add(JsonObject().apply {
                    addProperty("type", "public-key")
                    addProperty("alg", -7)
                })
            })
            addProperty("attestation", "none")
            add("excludeCredentials", excludeCredentials)
            add("authenticatorSelection", JsonObject().apply {
                addProperty("requireResidentKey", true)
                addProperty("residentKey", "required")
                addProperty("userVerification", "preferred")
            })
            addProperty("timeout", 300000)
        }.toString()

        val request = CreatePublicKeyCredentialRequest(
            requestJson = requestJson,
            preferImmediatelyAvailableCredentials = false,
        )

        Log.d(TAG, "register: calling createCredential — challenge=${options.challenge.take(16)}…")
        return try {
            val response = credentialManager.createCredential(context as Activity, request)
            val json = (response as CreatePublicKeyCredentialResponse).registrationResponseJson
            Log.d(TAG, "register: success — response ${json.length} chars")
            json
        } catch (e: CreateCredentialException) {
            val message = handleRegistrationFailure(e)
            Log.e(TAG, "register: failed — $message", e)
            throw Exception(message)
        }
    }

    suspend fun authenticate(options: PasskeyAuthenticationOptions): String {
        val requestJson = JsonObject().apply {
            addProperty("challenge", options.challenge)
            addProperty("rpId", options.rpId)
            addProperty("userVerification", options.userVerification ?: "preferred")
            addProperty("timeout", options.timeout ?: 300000)
            options.allowCredentials?.takeIf { it.isNotEmpty() }?.let { creds ->
                add("allowCredentials", JsonArray().apply {
                    creds.forEach { cred ->
                        add(JsonObject().apply {
                            addProperty("id", cred.id)
                            addProperty("type", cred.type)
                            cred.transports?.let { t ->
                                add("transports", JsonArray().apply { t.forEach { add(it) } })
                            }
                        })
                    }
                })
            }
        }.toString()

        val option = GetPublicKeyCredentialOption(requestJson = requestJson)
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .build()

        val credIds = options.allowCredentials?.joinToString { it.id.take(12) + "…" } ?: "none"
        Log.d(TAG, "authenticate: calling getCredential — rpId=${options.rpId} challenge=${options.challenge.take(16)}… allowCredentials=[$credIds]")
        return try {
            val response = credentialManager.getCredential(context as Activity, request)
            val json = (response.credential as PublicKeyCredential).authenticationResponseJson
            Log.d(TAG, "authenticate: success — response ${json.length} chars")
            json
        } catch (e: GetCredentialException) {
            val message = handleAuthenticationFailure(e)
            Log.e(TAG, "authenticate: failed [${e::class.simpleName}] — $message", e)
            throw Exception(message)
        }
    }

    private fun handleRegistrationFailure(e: CreateCredentialException): String =
        when (e) {
            is CreatePublicKeyCredentialDomException ->
                "Passkey DOM error: ${e.domError}"
            is CreateCredentialCancellationException ->
                "Registration cancelled by user"
            is CreateCredentialInterruptedException ->
                "Registration interrupted — please retry"
            is CreateCredentialProviderConfigurationException ->
                "Missing credential provider configuration"
            is CreateCredentialCustomException ->
                "Custom credential error: ${e.type}"
            else -> "Registration failed: ${e.message}"
        }

    private fun handleAuthenticationFailure(e: GetCredentialException): String =
        when (e) {
            is GetCredentialCancellationException ->
                "Login cancelled by user"
            is NoCredentialException ->
                "No passkey found — register first"
            is GetCredentialInterruptedException ->
                "Login interrupted — please retry"
            is GetCredentialProviderConfigurationException ->
                "Missing credential provider configuration"
            is GetCredentialCustomException ->
                "Custom credential error: ${e.type}"
            else -> "Login failed: ${e.message}"
        }
}
