package com.example.dlaauth.service

import android.util.Log
import com.example.dlaauth.model.ApprovalDecision
import com.example.dlaauth.model.ApprovalRequestItem
import com.example.dlaauth.model.DeviceChallengeRequest
import com.example.dlaauth.model.DeviceChallengeResponse
import com.example.dlaauth.model.DeviceFinalizeRequest
import com.example.dlaauth.model.DeviceFinalizeResponse
import com.example.dlaauth.model.DeviceListItem
import com.example.dlaauth.model.ApprovalStatusResponse
import com.example.dlaauth.model.DeviceVerifyRequest
import com.example.dlaauth.model.DeviceVerifyResponse
import com.example.dlaauth.model.LoginOptionsResponse
import com.example.dlaauth.model.PasskeyAuthenticationOptions
import com.example.dlaauth.model.PasskeyRegistrationOptions
import com.example.dlaauth.model.RegisterOptionsResponse
import com.example.dlaauth.model.SessionInfo
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

object APIClient {

    const val BASE_URL = "https://dla.metaauth.site"

    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    private val gson = Gson()

    // ---------------------------------------------------------------------------
    // In-memory CookieJar — persists connect.sid across requests
    // ---------------------------------------------------------------------------

    private val cookieStore = mutableMapOf<String, List<Cookie>>()

    private val cookieJar = object : CookieJar {
        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            cookieStore[url.host] = cookies
        }

        override fun loadForRequest(url: HttpUrl): List<Cookie> =
            cookieStore[url.host] ?: emptyList()
    }

    private val client = OkHttpClient.Builder()
        .cookieJar(cookieJar)
        .build()

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    private fun buildJsonBody(json: String) =
        json.toRequestBody(JSON_MEDIA_TYPE)

    private fun buildJsonBody(obj: Any) =
        gson.toJson(obj).toRequestBody(JSON_MEDIA_TYPE)

    private fun executeRequest(request: Request): String {
        val response: Response = client.newCall(request).execute()
        val body = response.body?.string() ?: ""

        if (!response.isSuccessful) {
            val message = runCatching {
                gson.fromJson(body, JsonObject::class.java)
                    ?.get("error")?.asString
                    ?: gson.fromJson(body, JsonObject::class.java)
                        ?.get("message")?.asString
            }.getOrNull() ?: "HTTP ${response.code}"
            throw Exception(message)
        }
        return body
    }

    private suspend fun get(path: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$BASE_URL$path")
            .get()
            .build()
        executeRequest(request)
    }

    private suspend fun post(path: String, bodyJson: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$BASE_URL$path")
            .post(buildJsonBody(bodyJson))
            .build()
        executeRequest(request)
    }

    private suspend fun post(path: String, body: Any): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$BASE_URL$path")
            .post(buildJsonBody(body))
            .build()
        executeRequest(request)
    }

    private suspend fun postEmpty(path: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$BASE_URL$path")
            .post("{}".toRequestBody(JSON_MEDIA_TYPE))
            .build()
        executeRequest(request)
    }

    private inline fun <reified T> parse(json: String): T =
        gson.fromJson(json, object : TypeToken<T>() {}.type)

    // ---------------------------------------------------------------------------
    // WebAuthn Passkey
    // ---------------------------------------------------------------------------

    suspend fun registerOptions(username: String): RegisterOptionsResponse {
        val body = gson.toJson(mapOf("email" to username))
        return parse(post("/webauthn/register/options", body))
    }

    suspend fun registerVerify(userId: String, credentialJSON: String): JsonObject {
        val body = JsonObject().apply {
            addProperty("userId", userId)
            add("response", gson.fromJson(credentialJSON, JsonObject::class.java))
        }
        return parse(post("/webauthn/register/verify", body.toString()))
    }

    suspend fun loginOptions(username: String): LoginOptionsResponse {
        val body = gson.toJson(mapOf("email" to username))
        return parse(post("/webauthn/authenticate/options", body))
    }

    suspend fun loginVerify(userId: String, credentialJSON: String): JsonObject {
        val body = JsonObject().apply {
            addProperty("userId", userId)
            add("response", gson.fromJson(credentialJSON, JsonObject::class.java))
        }
        return parse(post("/webauthn/authenticate/verify", body.toString()))
    }

    // ---------------------------------------------------------------------------
    // DLA Device Layer
    // ---------------------------------------------------------------------------

    suspend fun deviceChallenge(dbkPublicKey: Map<String, String>): DeviceChallengeResponse =
        parse(post("/api/device/challenge", DeviceChallengeRequest(dbkPublicKey)))

    suspend fun deviceVerify(request: DeviceVerifyRequest): DeviceVerifyResponse =
        parse(post("/api/device/verify", request))

    suspend fun approvalStatus(requestId: String): ApprovalStatusResponse =
        parse(get("/api/device/status/$requestId"))

    suspend fun deviceFinalize(request: DeviceFinalizeRequest): DeviceFinalizeResponse =
        parse(post("/api/device/finalize", request))

    suspend fun pendingApprovals(): List<ApprovalRequestItem> {
        val json = get("/api/device/approval/pending")
        val wrapper = gson.fromJson(json, JsonObject::class.java)
        return gson.fromJson(
            wrapper.getAsJsonArray("pending"),
            object : TypeToken<List<ApprovalRequestItem>>() {}.type
        )
    }

    suspend fun approvalDecide(request: ApprovalDecision): JsonObject =
        parse(post("/api/device/approval/decide", request))

    suspend fun deviceList(): List<DeviceListItem> {
        val json = get("/api/device/list")
        val wrapper = gson.fromJson(json, JsonObject::class.java)
        return gson.fromJson(
            wrapper.getAsJsonArray("devices"),
            object : TypeToken<List<DeviceListItem>>() {}.type
        )
    }

    suspend fun sessionInfo(): SessionInfo =
        parse(get("/api/session"))

    suspend fun logout() {
        postEmpty("/api/logout")
    }
}
