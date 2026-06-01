package com.example.dlaauth.service

import android.app.Activity
import android.app.Application
import android.content.Context
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.lang.ref.WeakReference
import com.example.dlaauth.model.ApprovalDecision
import com.example.dlaauth.model.ApprovalRequestItem
import com.example.dlaauth.model.ClientMetrics
import com.example.dlaauth.model.DeviceFinalizeRequest
import com.example.dlaauth.model.DeviceListItem
import com.example.dlaauth.model.DeviceVerifyRequest
import com.example.dlaauth.util.DeviceInfo
import com.example.dlaauth.util.LatencyLogger
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

sealed class AuthState {
    object Idle : AuthState()
    object Registering : AuthState()
    object Authenticating : AuthState()
    object DeviceVerifying : AuthState()
    data class PendingApproval(val deviceId: String) : AuthState()
    object Authenticated : AuthState()
    data class RegisterSuccess(val username: String) : AuthState()
    data class Error(val message: String) : AuthState()
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

enum class LogType { INFO, SUCCESS, ERROR, FLOW }

data class LogEntry(val timestamp: Long, val message: String, val type: LogType)

// ---------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------

data class LatencyMetrics(
    var passkeyAuthMs: Double? = null,
    var dbkGenerationMs: Double? = null,
    var dbkSigningMs: Double? = null,
    var deviceVerifyMs: Double? = null,
    var totalAuthMs: Double? = null,
)

data class IterationResult(
    val run: Int,
    val passkeyMs: Long,
    val dbkLoadMs: Long,
    val dbkSignMs: Long,
    val verifyMs: Long,
    val totalMs: Long,
)

data class DBKStatus(
    val exists: Boolean = false,
    val hardware: String = "Software",
    val keyAlias: String = "com.example.dlaauth.dbk",
    val backingLevel: KeyBackingLevel = KeyBackingLevel.UNKNOWN,
)

// ---------------------------------------------------------------------------
// ViewModel
// ---------------------------------------------------------------------------

class DLAAuthManager(application: Application) : AndroidViewModel(application) {

    private val TAG = "DLAAuth"
    private val BENCH = "BENCH"
    private var runCounter = 0

    // --- StateFlow ---

    private val _state = MutableStateFlow<AuthState>(AuthState.Idle)
    val state = _state.asStateFlow()

    val username = MutableStateFlow("")

    private val _logEntries = MutableStateFlow<List<LogEntry>>(emptyList())
    val logEntries = _logEntries.asStateFlow()

    private val _devices = MutableStateFlow<List<DeviceListItem>>(emptyList())
    val devices = _devices.asStateFlow()

    private val _pendingApprovals = MutableStateFlow<List<ApprovalRequestItem>>(emptyList())
    val pendingApprovals = _pendingApprovals.asStateFlow()

    private val _latencyMetrics = MutableStateFlow(LatencyMetrics())
    val latencyMetrics = _latencyMetrics.asStateFlow()

    private val _dbkStatus = MutableStateFlow(DBKStatus())
    val dbkStatus = _dbkStatus.asStateFlow()

    // --- Dependencies ---

    private val apiClient = APIClient
    private var passkeyService: PasskeyService? = null
    private val dbkService = KeyStoreDBKService()

    private var activityRef: WeakReference<Activity>? = null
    private val activity: Activity? get() = activityRef?.get()

    // Pending approval state
    private var pendingRequestId: String? = null
    private var pendingLoginAttemptId: String? = null

    // Background polling for incoming approval requests (runs on trusted device)
    private var approvalPollingJob: Job? = null

    // ---------------------------------------------------------------------------
    // Setup
    // ---------------------------------------------------------------------------

    fun setActivity(activity: Activity) {
        activityRef = WeakReference(activity)
        passkeyService = PasskeyService(activity)
        loadDBKStatus(getApplication())
    }

    // ---------------------------------------------------------------------------
    // Logging
    // ---------------------------------------------------------------------------

    private fun log(message: String, type: LogType) {
        val entry = LogEntry(System.currentTimeMillis(), message, type)
        _logEntries.value = _logEntries.value + entry
    }

    // ---------------------------------------------------------------------------
    // Register
    // ---------------------------------------------------------------------------

    fun register() {
        viewModelScope.launch {
            _state.value = AuthState.Registering
            log("Starting passkey registration...", LogType.FLOW)
            try {
                val wrapper = apiClient.registerOptions(username.value)
                log("Received registration options", LogType.INFO)
                val credentialJSON = passkeyService!!.register(wrapper.options)
                log("Passkey created by device", LogType.INFO)
                val result = apiClient.registerVerify(wrapper.userId, credentialJSON)
                val registeredUser = result.get("username")?.asString ?: username.value
                log("Passkey registered successfully for $registeredUser", LogType.SUCCESS)
                _state.value = AuthState.RegisterSuccess(registeredUser)
                return@launch
            } catch (e: Exception) {
                log("Registration failed: ${e.message}", LogType.ERROR)
                _state.value = AuthState.Error(e.message ?: "Registration failed")
                return@launch
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Login — two-layer DLA flow
    // ---------------------------------------------------------------------------

    fun login() {
        viewModelScope.launch {
            _state.value = AuthState.Authenticating
            _latencyMetrics.value = LatencyMetrics()
            LatencyLogger.reset()
            val totalStart = System.nanoTime()
            val run = ++runCounter
            Log.d(TAG, "── run=$run start ──────────────────────────")

            // ════════════════════════════════════════════
            // LAYER 1: Passkey Authentication (proves USER)
            // ════════════════════════════════════════════
            log("═══ Layer 1: Passkey Authentication ═══", LogType.FLOW)

            val loginResult = try {
                val wrapper = apiClient.loginOptions(username.value)
                log("Received authentication challenge", LogType.INFO)
                val credentialJSON = passkeyService!!.authenticate(wrapper.options)
                log("Passkey assertion completed", LogType.INFO)
                val (result, passkeyMs) = LatencyLogger.measure("passkey_auth") {
                    apiClient.loginVerify(wrapper.userId, credentialJSON)
                }
                _latencyMetrics.value = _latencyMetrics.value.copy(passkeyAuthMs = passkeyMs)
                log("✓ User identity verified via passkey", LogType.SUCCESS)
                result
            } catch (e: Exception) {
                // PASSKEY FAILED → STOP HERE. DLA never runs.
                log("✗ Passkey authentication failed: ${e.message}", LogType.ERROR)
                _state.value = AuthState.Error("Passkey failed: ${e.message}")
                return@launch // ← CRITICAL: do NOT proceed to Layer 2
            }

            // Check if server requires device verification
            val nextStep = loginResult.get("nextStep")?.asString
            if (nextStep != "DEVICE_VERIFICATION") {
                log("Authentication complete (no DLA required)", LogType.SUCCESS)
                _state.value = AuthState.Authenticated
                return@launch
            }

            // ════════════════════════════════════════════
            // LAYER 2: DLA Device Verification
            // ════════════════════════════════════════════
            _state.value = AuthState.DeviceVerifying
            log("═══ Layer 2: Device Legitimacy Assessment ═══", LogType.FLOW)

            try {
                val ctx: Context = getApplication()

                // Step 2a: Get or generate DBK public key (FIRST)
                val keyExistedBefore = dbkService.keyExists()
                val dbkStart = System.nanoTime()
                val dbkPublicKey = dbkService.getPublicKeyJWK(ctx)
                val dbkGenMs = (System.nanoTime() - dbkStart) / 1_000_000.0
                val backingLevel = dbkService.verifyKeyBackingLevel()

                _latencyMetrics.value = _latencyMetrics.value.copy(dbkGenerationMs = dbkGenMs)
                val keyAction = if (keyExistedBefore) "Loaded existing" else "Generated new"
                log("$keyAction EC P-256 key pair [${backingLevel.displayName()}] in ${dbkGenMs.toLong()}ms", LogType.INFO)
                log("DBK pub x: ${dbkPublicKey["x"]?.take(12)}…  y: ${dbkPublicKey["y"]?.take(12)}…", LogType.INFO)

                // Step 2b: Send pubKey to /challenge
                val challengeResponse = apiClient.deviceChallenge(dbkPublicKey)
                log("Challenge received — trusted devices: ${challengeResponse.trustedDeviceCount}, bootstrap: ${challengeResponse.isBootstrap}", LogType.INFO)
                log("Challenge: ${challengeResponse.challenge.take(16)}…", LogType.INFO)

                // Step 2c: Sign challenge with DBK private key
                val signStart = System.nanoTime()
                val signature = dbkService.sign(challengeResponse.challenge, ctx)
                val signMs = (System.nanoTime() - signStart) / 1_000_000.0

                _latencyMetrics.value = _latencyMetrics.value.copy(dbkSigningMs = signMs)
                log("Signed in ${signMs.toLong()}ms — signature: ${signature.take(16)}…", LogType.INFO)

                // Step 2d: Collect signals and send signature only
                val signals = DeviceInfo.collectSignals()
                val clientMetricsData = ClientMetrics(
                    dbkGenMs = dbkGenMs,
                    dbkSignMs = signMs
                )

                val verifyStart = System.nanoTime()
                val response = apiClient.deviceVerify(DeviceVerifyRequest(
                    signature = signature,
                    signals = signals,
                    clientMetrics = clientMetricsData
                ))
                val verifyMs = (System.nanoTime() - verifyStart) / 1_000_000.0
                val totalMs = (System.nanoTime() - totalStart) / 1_000_000.0

                _latencyMetrics.value = _latencyMetrics.value.copy(
                    deviceVerifyMs = verifyMs,
                    totalAuthMs = totalMs
                )

                // Step 2e: Handle flow result
                log("Flow: ${response.flow}, Status: ${response.status}", LogType.FLOW)
                when (response.flow) {
                    "BOOTSTRAP" -> {
                        _state.value = AuthState.Authenticated
                        log("✓ First device enrolled and trusted", LogType.SUCCESS)
                        startApprovalPolling()
                    }
                    "TRUSTED_DEVICE" -> {
                        _state.value = AuthState.Authenticated
                        log("✓ Known trusted device. Access granted", LogType.SUCCESS)
                        startApprovalPolling()
                    }
                    "NEW_DEVICE" -> {
                        pendingRequestId = response.requestId
                        pendingLoginAttemptId = response.loginAttemptId
                        _state.value = AuthState.PendingApproval(response.deviceId)
                        log("⏳ New device detected. Awaiting approval...", LogType.INFO)
                        log("Request ID: ${response.requestId}", LogType.INFO)
                        pollForApproval(response.requestId!!)
                    }
                    "NEWLY_APPROVED" -> {
                        _state.value = AuthState.Authenticated
                        log("✓ Device approved and now trusted", LogType.SUCCESS)
                        startApprovalPolling()
                    }
                    "BLOCKED" -> {
                        _state.value = AuthState.Error("Device is ${response.status}")
                        log("✗ Device blocked", LogType.ERROR)
                    }
                }

                log("Latency — Passkey: ${_latencyMetrics.value.passkeyAuthMs?.toLong()}ms, " +
                    "DBK Gen: ${dbkGenMs.toLong()}ms, " +
                    "DBK Sign: ${signMs.toLong()}ms, " +
                    "Total: ${totalMs.toLong()}ms", LogType.INFO)
                Log.d(TAG, "── run=$run end — passkey=${_latencyMetrics.value.passkeyAuthMs?.toLong()} dbk_gen=${dbkGenMs.toLong()} dbk_sign=${signMs.toLong()} verify=${verifyMs.toLong()} total=${totalMs.toLong()} ──")

            } catch (e: Exception) {
                log("✗ Device verification failed: ${e.message}", LogType.ERROR)
                _state.value = AuthState.Error("DLA failed: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Approval polling
    // ---------------------------------------------------------------------------

    private suspend fun pollForApproval(requestId: String) {
        var attempts = 0
        while (attempts < 60) {
            delay(5000)
            try {
                val status = apiClient.approvalStatus(requestId)
                when (status.approvalStatus) {
                    "APPROVED" -> {
                        log("✓ Approval granted by trusted device", LogType.SUCCESS)
                        log("Performing finalization with fresh signature...", LogType.INFO)
                        performFinalization()
                        return
                    }
                    "DENIED" -> {
                        _state.value = AuthState.Error("Device was rejected")
                        log("✗ Trusted device denied approval", LogType.ERROR)
                        return
                    }
                    "EXPIRED" -> {
                        _state.value = AuthState.Error("Approval expired")
                        log("✗ Approval request expired", LogType.ERROR)
                        return
                    }
                    "PENDING" -> {
                        attempts++
                        if (attempts % 6 == 0) {
                            log("Still waiting... (${attempts * 5}s)", LogType.INFO)
                        }
                    }
                    "CONSUMED" -> {
                        _state.value = AuthState.Authenticated
                        return
                    }
                }
            } catch (e: Exception) {
                log("Polling error: ${e.message}", LogType.ERROR)
            }
        }
        _state.value = AuthState.Error("Approval timeout (5 minutes)")
    }

    private suspend fun performFinalization() {
        val requestId = pendingRequestId
        val loginAttemptId = pendingLoginAttemptId

        if (requestId == null || loginAttemptId == null) {
            _state.value = AuthState.Error("Missing approval IDs")
            return
        }

        _state.value = AuthState.DeviceVerifying
        log("═══ Finalization: requesting fresh challenge ═══", LogType.FLOW)

        try {
            val ctx = activity!!.applicationContext

            // STEP 1: Get FRESH challenge (challenge_2)
            val dbkPublicKey = dbkService.getPublicKeyJWK(ctx)
            val challengeResponse = apiClient.deviceChallenge(dbkPublicKey)
            log("Fresh challenge received for finalization", LogType.INFO)

            // STEP 2: Sign fresh challenge
            val signStart = System.nanoTime()
            val signature = dbkService.sign(challengeResponse.challenge, ctx)
            val signMs = (System.nanoTime() - signStart) / 1_000_000.0
            log("Fresh signature generated (${signMs.toLong()}ms)", LogType.INFO)

            // STEP 3: Send to /finalize
            val response = apiClient.deviceFinalize(DeviceFinalizeRequest(
                requestId = requestId,
                loginAttemptId = loginAttemptId,
                signature = signature
            ))

            if (response.authComplete) {
                _state.value = AuthState.Authenticated
                log("✓ Finalization complete. Device now TRUSTED", LogType.SUCCESS)
                pendingRequestId = null
                pendingLoginAttemptId = null
            } else {
                _state.value = AuthState.Error("Finalization incomplete")
            }
        } catch (e: Exception) {
            log("✗ Finalization failed: ${e.message}", LogType.ERROR)
            _state.value = AuthState.Error("Finalize failed: ${e.message}")
        }
    }

    // ---------------------------------------------------------------------------
    // Trusted-device approval polling
    // ---------------------------------------------------------------------------

    fun startApprovalPolling() {
        approvalPollingJob?.cancel()
        approvalPollingJob = viewModelScope.launch {
            while (isActive) {
                try {
                    val pending = apiClient.pendingApprovals()
                    _pendingApprovals.value = pending
                    if (pending.isNotEmpty()) {
                        break  // stop polling; UI shows approval cards
                    }
                } catch (e: Exception) {
                    log("Approval poll error: ${e.message}", LogType.ERROR)
                }
                delay(10_000)
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Device management
    // ---------------------------------------------------------------------------

    fun loadDevices() {
        viewModelScope.launch {
            try {
                _devices.value = apiClient.deviceList()
            } catch (e: Exception) {
                log("Failed to load devices: ${e.message}", LogType.ERROR)
            }
        }
    }

    fun loadPendingApprovals() {
        viewModelScope.launch {
            try {
                _pendingApprovals.value = apiClient.pendingApprovals()
            } catch (e: Exception) {
                log("Failed to load pending approvals: ${e.message}", LogType.ERROR)
            }
        }
    }

    fun getDBKStatus(context: Context, precomputedLevel: KeyBackingLevel? = null): DBKStatus {
        val hardware = when {
            DeviceInfo.isStrongBoxAvailable(context) -> "StrongBox"
            DeviceInfo.isTEEAvailable() -> "TEE"
            else -> "Software"
        }
        val backingLevel = precomputedLevel ?: dbkService.verifyKeyBackingLevel()
        return DBKStatus(
            exists = dbkService.keyExists(),
            hardware = hardware,
            backingLevel = backingLevel,
        )
    }

    fun loadDBKStatus(context: Context, precomputedLevel: KeyBackingLevel? = null) {
        _dbkStatus.value = getDBKStatus(context, precomputedLevel)
    }

    fun approveDevice(item: ApprovalRequestItem) {
        viewModelScope.launch {
            try {
                val ctx: Context = getApplication()
                val canonical = buildCanonical("APPROVED", item.requestId, item.loginAttemptId)
                val signature = dbkService.signMessage(canonical, ctx)
                apiClient.approvalDecide(ApprovalDecision(
                    requestId = item.requestId,
                    decision = "APPROVED",
                    signature = signature,
                    canonicalPayload = canonical,
                ))
                log("Device approved (signed)", LogType.SUCCESS)
                startApprovalPolling()
            } catch (e: Exception) {
                log("Approve failed: ${e.message}", LogType.ERROR)
            }
        }
    }

    fun denyDevice(item: ApprovalRequestItem) {
        viewModelScope.launch {
            try {
                val ctx: Context = getApplication()
                val canonical = buildCanonical("DENIED", item.requestId, item.loginAttemptId)
                val signature = dbkService.signMessage(canonical, ctx)
                apiClient.approvalDecide(ApprovalDecision(
                    requestId = item.requestId,
                    decision = "DENIED",
                    signature = signature,
                    canonicalPayload = canonical,
                ))
                log("Device denied (signed)", LogType.INFO)
                startApprovalPolling()
            } catch (e: Exception) {
                log("Deny failed: ${e.message}", LogType.ERROR)
            }
        }
    }

    private fun buildCanonical(decision: String, requestId: String, loginAttemptId: String?): String =
        if (loginAttemptId != null) "$decision:$requestId:$loginAttemptId"
        else "$decision:$requestId"

    fun resetDBK() {
        viewModelScope.launch {
            dbkService.deleteKey()
            loadDBKStatus(getApplication())
            log("DBK deleted — device will appear as new on next login", LogType.INFO)
        }
    }

    fun logout() {
        approvalPollingJob?.cancel()
        approvalPollingJob = null
        viewModelScope.launch {
            try {
                apiClient.logout()
            } catch (e: Exception) {
                log("Logout error: ${e.message}", LogType.ERROR)
            }
            _state.value = AuthState.Idle
            _pendingApprovals.value = emptyList()
            log("Logged out", LogType.INFO)
        }
    }

    // ---------------------------------------------------------------------------
    // Benchmark — trusted-device flow, N iterations
    // ---------------------------------------------------------------------------

    private suspend fun timedLogin(run: Int): IterationResult {
        val ctx: Context = getApplication()
        val totalStart = System.currentTimeMillis()

        // ── Passkey: options + getCredential + loginVerify ──
        val passkeyStart = System.currentTimeMillis()
        val wrapper = apiClient.loginOptions(username.value)
        val credentialJSON = passkeyService!!.authenticate(wrapper.options)
        apiClient.loginVerify(wrapper.userId, credentialJSON)
        val passkeyMs = System.currentTimeMillis() - passkeyStart

        // ── DBK key load ──
        val loadStart = System.currentTimeMillis()
        val dbkPublicKey = dbkService.getPublicKeyJWK(ctx)
        val dbkLoadMs = System.currentTimeMillis() - loadStart

        // ── Challenge (network — excluded from device timing) ──
        val challengeResponse = apiClient.deviceChallenge(dbkPublicKey)

        // ── DBK sign ──
        val signStart = System.currentTimeMillis()
        val signature = dbkService.sign(challengeResponse.challenge, ctx)
        val dbkSignMs = System.currentTimeMillis() - signStart

        // ── Device verify ──
        val signals = DeviceInfo.collectSignals()
        val verifyStart = System.currentTimeMillis()
        val verifyResponse = apiClient.deviceVerify(DeviceVerifyRequest(
            signature = signature,
            signals = signals,
        ))
        val verifyMs = System.currentTimeMillis() - verifyStart
        val totalMs = System.currentTimeMillis() - totalStart

        check(verifyResponse.flow in listOf("TRUSTED_DEVICE", "NEWLY_APPROVED")) {
            "Benchmark requires a trusted device — got flow=${verifyResponse.flow}"
        }

        Log.i(BENCH, "run=$run passkey=$passkeyMs dbkLoad=$dbkLoadMs dbkSign=$dbkSignMs verify=$verifyMs total=$totalMs")
        return IterationResult(run, passkeyMs, dbkLoadMs, dbkSignMs, verifyMs, totalMs)
    }

    fun runBenchmark(iterations: Int = 30) {
        viewModelScope.launch {
            Log.i(BENCH, "=== benchmark start  iterations=$iterations user=${username.value} ===")
            val results = mutableListOf<IterationResult>()
            repeat(iterations) { i ->
                Log.i(BENCH, "=== Iteration ${i + 1} ===")
                try {
                    results.add(timedLogin(i + 1))
                } catch (e: Exception) {
                    Log.e(BENCH, "Iteration ${i + 1} failed: ${e.message}")
                }
                apiClient.logout()
                delay(2000)
            }
            if (results.isEmpty()) return@launch

            fun List<Long>.p50(): Long = sorted().let { it[it.size / 2] }
            fun List<Long>.p95(): Long = sorted().let { it[(it.size * 0.95).toInt().coerceAtMost(it.lastIndex)] }

            Log.i(BENCH, "=== SUMMARY  n=${results.size} ===")
            Log.i(BENCH, String.format("%-10s %6s %6s", "metric", "P50", "P95"))
            for ((label, selector) in listOf(
                "passkey"  to IterationResult::passkeyMs,
                "dbkLoad"  to IterationResult::dbkLoadMs,
                "dbkSign"  to IterationResult::dbkSignMs,
                "verify"   to IterationResult::verifyMs,
                "total"    to IterationResult::totalMs,
            )) {
                val vals = results.map { selector(it) }
                Log.i(BENCH, String.format("%-10s %6d %6d", label, vals.p50(), vals.p95()))
            }
            Log.i(BENCH, "=== benchmark end ===")
        }
    }
}
