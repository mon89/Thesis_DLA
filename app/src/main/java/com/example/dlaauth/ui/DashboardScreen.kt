package com.example.dlaauth.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.dlaauth.model.ApprovalRequestItem
import com.example.dlaauth.model.DeviceListItem
import com.example.dlaauth.service.DBKStatus
import com.example.dlaauth.service.DLAAuthManager
import com.example.dlaauth.service.KeyBackingLevel
import com.example.dlaauth.service.LatencyMetrics

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(authManager: DLAAuthManager) {
    val context = LocalContext.current
    val devices by authManager.devices.collectAsStateWithLifecycle()
    val pendingApprovals by authManager.pendingApprovals.collectAsStateWithLifecycle()
    val latencyMetrics by authManager.latencyMetrics.collectAsStateWithLifecycle()
    val dbkStatus by authManager.dbkStatus.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        authManager.loadDevices()
        authManager.loadPendingApprovals()
        authManager.loadDBKStatus(context.applicationContext)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("DLA Auth — Dashboard") },
                actions = {
                    IconButton(onClick = { authManager.loadPendingApprovals() }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Spacer(Modifier.height(4.dp))

            // Action bar
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        authManager.loadDevices()
                        authManager.loadPendingApprovals()
                        authManager.loadDBKStatus(context.applicationContext)
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Refresh") }

                Button(
                    onClick = { authManager.logout() },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) { Text("Logout") }
            }

            OutlinedButton(
                onClick = { authManager.runBenchmark(30) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Run Benchmark (30 iterations) — see tag:BENCH in Logcat") }

            // Latency metrics
            val m = latencyMetrics
            if (m.totalAuthMs != null) {
                LatencyMetricsCard(metrics = m)
            }

            PendingApprovalsSection(
                pendingApprovals = pendingApprovals,
                onApprove = { item -> authManager.approveDevice(item) },
                onDeny = { item -> authManager.denyDevice(item) },
            )

            Text(
                text = "Hardware Security Status",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
            HardwareSecurityStatusCard(status = dbkStatus)

            // Registered devices
            Text(
                text = "Registered Devices (${devices.size})",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
            if (devices.isEmpty()) {
                Text(
                    text = "No devices found",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                devices.forEach { device ->
                    DeviceCard(device)
                }
            }

            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
fun PendingApprovalsSection(
    pendingApprovals: List<ApprovalRequestItem>,
    onApprove: (ApprovalRequestItem) -> Unit,
    onDeny: (ApprovalRequestItem) -> Unit,
) {
    if (pendingApprovals.isEmpty()) return

    Card(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "Pending Device Approvals (${pendingApprovals.size})",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(8.dp))
            pendingApprovals.forEach { approval ->
                ApprovalCard(
                    item = approval,
                    onApprove = { onApprove(approval) },
                    onDeny = { onDeny(approval) },
                )
                Spacer(Modifier.height(4.dp))
            }
        }
    }
}

@Composable
private fun HardwareSecurityStatusCard(status: DBKStatus) {
    val backing = status.backingLevel
    val statusColor = when {
        backing.isSecure() -> Color(0xFF2E7D32)        // green
        backing == KeyBackingLevel.SOFTWARE -> Color(0xFFC62828)  // red
        else -> Color(0xFF757575)                       // gray
    }
    val icon = when {
        backing.isSecure() -> Icons.Filled.Security
        backing == KeyBackingLevel.SOFTWARE -> Icons.Outlined.Warning
        else -> Icons.Filled.LockOpen
    }
    val statusText = if (status.exists) "Present" else "Not Created"

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = statusColor,
                )
                Text(
                    text = "Hardware Security",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }
            StatusRow(label = "DBK Status:", value = statusText, valueColor = statusColor)
            StatusRow(
                label = "Backing (verified):",
                value = backing.displayName(),
                valueColor = statusColor,
            )
            StatusRow(label = "Device hardware:", value = status.hardware)
            StatusRow(
                label = "Key Alias:",
                value = status.keyAlias,
                monospace = true,
            )
        }
    }
}

@Composable
private fun StatusRow(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
    monospace: Boolean = false,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.42f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            color = valueColor,
            modifier = Modifier.weight(0.58f),
        )
    }
}

@Composable
private fun ApprovalCard(
    item: ApprovalRequestItem,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
) {
    val timeRemaining by produceState(initialValue = formatTimeRemaining(item.expiresAt)) {
        while (true) {
            kotlinx.coroutines.delay(1_000)
            value = formatTimeRemaining(item.expiresAt)
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = "New device requesting access",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                text = "Device: ${item.requestingDeviceId.take(16)}...",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            item.requestContext?.let { ctx ->
                if (ctx.platform.isNotBlank()) {
                    Text(
                        text = "Platform: ${ctx.platform}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
                if (ctx.userAgent.isNotBlank()) {
                    Text(
                        text = "UA: ${ctx.userAgent.take(60)}${if (ctx.userAgent.length > 60) "…" else ""}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
                ctx.ip?.let { ip ->
                    Text(
                        text = "IP: $ip",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
            if (timeRemaining.isNotEmpty()) {
                Text(
                    text = timeRemaining,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (timeRemaining.startsWith("Expired"))
                        MaterialTheme.colorScheme.error
                    else
                        MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onApprove, modifier = Modifier.weight(1f)) {
                    Text("Approve")
                }
                OutlinedButton(
                    onClick = onDeny,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Deny")
                }
            }
        }
    }
}

private fun formatTimeRemaining(expiresAt: String?): String {
    if (expiresAt == null) return ""
    return try {
        val sdf = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
        sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
        val expiry = sdf.parse(expiresAt) ?: return ""
        val remaining = (expiry.time - System.currentTimeMillis()) / 1000
        if (remaining <= 0) "Expired" else "Expires in ${remaining / 60}m ${remaining % 60}s"
    } catch (e: Exception) {
        ""
    }
}

@Composable
private fun DeviceCard(device: DeviceListItem) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = device.deviceId.take(20) + "...",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                device.createdAt?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            StatusBadge(status = device.status)
        }
    }
}

@Composable
private fun StatusBadge(status: String) {
    val (bg, fg) = when (status.uppercase()) {
        "TRUSTED" -> Color(0xFF2E7D32) to Color.White
        "PENDING" -> Color(0xFFE65100) to Color.White
        "REJECTED" -> Color(0xFFC62828) to Color.White
        else -> Color(0xFF616161) to Color.White
    }
    Surface(
        color = bg,
        shape = RoundedCornerShape(4.dp),
    ) {
        Text(
            text = status,
            color = fg,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}
