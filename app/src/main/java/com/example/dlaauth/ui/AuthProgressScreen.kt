package com.example.dlaauth.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.dlaauth.service.AuthState
import com.example.dlaauth.service.DLAAuthManager
import com.example.dlaauth.service.LogEntry
import com.example.dlaauth.service.LogType

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthProgressScreen(authManager: DLAAuthManager) {
    val state by authManager.state.collectAsStateWithLifecycle()
    val logEntries by authManager.logEntries.collectAsStateWithLifecycle()
    val latencyMetrics by authManager.latencyMetrics.collectAsStateWithLifecycle()

    val statusText = when (state) {
        is AuthState.Registering -> "Registering passkey..."
        is AuthState.Authenticating -> "Authenticating..."
        is AuthState.DeviceVerifying -> "Verifying device..."
        is AuthState.PendingApproval -> "Waiting for approval from trusted device..."
        else -> "Processing..."
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("DLA Auth — In Progress") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Status card
            Card(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = statusText,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }

            // Latency metrics (when available)
            val m = latencyMetrics
            if (m.passkeyAuthMs != null || m.dbkGenerationMs != null) {
                LatencyMetricsCard(metrics = m)
            }

            // Terminal log
            Text(
                text = "Authentication Log",
                style = MaterialTheme.typography.labelLarge,
            )

            val listState = rememberLazyListState()
            LaunchedEffect(logEntries.size) {
                if (logEntries.isNotEmpty()) {
                    listState.animateScrollToItem(logEntries.lastIndex)
                }
            }

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E)),
                shape = RoundedCornerShape(8.dp),
            ) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    items(logEntries) { entry ->
                        LogEntryRow(entry)
                    }
                }
            }
        }
    }
}

@Composable
private fun LogEntryRow(entry: LogEntry) {
    val color = when (entry.type) {
        LogType.INFO -> Color(0xFFAAAAAA)
        LogType.SUCCESS -> Color(0xFF4CAF50)
        LogType.ERROR -> Color(0xFFEF5350)
        LogType.FLOW -> Color(0xFF64B5F6)
    }
    Text(
        text = entry.message,
        color = color,
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
        modifier = Modifier.fillMaxWidth(),
    )
}