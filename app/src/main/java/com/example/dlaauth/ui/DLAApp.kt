package com.example.dlaauth.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.dlaauth.service.AuthState
import com.example.dlaauth.service.DLAAuthManager

@Composable
fun DLAApp(authManager: DLAAuthManager) {
    val state by authManager.state.collectAsStateWithLifecycle()

    when (val s = state) {
        is AuthState.Idle,
        is AuthState.Error,
        is AuthState.RegisterSuccess -> LoginScreen(authManager = authManager)

        is AuthState.Registering,
        is AuthState.Authenticating,
        is AuthState.DeviceVerifying -> AuthProgressScreen(authManager = authManager)

        is AuthState.PendingApproval -> AuthProgressScreen(authManager = authManager)

        is AuthState.Authenticated -> DashboardScreen(authManager = authManager)
    }
}