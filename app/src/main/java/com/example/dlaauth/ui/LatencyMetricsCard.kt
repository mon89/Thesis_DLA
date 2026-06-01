package com.example.dlaauth.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.dlaauth.service.LatencyMetrics
import com.example.dlaauth.util.DeviceInfo
import android.content.Context
import androidx.compose.ui.platform.LocalContext

@Composable
fun LatencyMetricsCard(metrics: LatencyMetrics) {
    val context = LocalContext.current
    val securityHardware = if (DeviceInfo.isStrongBoxAvailable(context)) "StrongBox" else "TEE"

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = "Latency Metrics",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(8.dp))
            metrics.passkeyAuthMs?.let {
                MetricRow(label = "Passkey Auth", valueMs = it)
            }
            metrics.dbkGenerationMs?.let {
                MetricRow(label = "DBK Gen ($securityHardware)", valueMs = it)
            }
            metrics.dbkSigningMs?.let {
                MetricRow(label = "DBK Sign ($securityHardware)", valueMs = it)
            }
            metrics.deviceVerifyMs?.let {
                MetricRow(label = "Device Verify (RTT)", valueMs = it)
            }
            metrics.totalAuthMs?.let {
                Spacer(Modifier.height(4.dp))
                MetricRow(
                    label = "Total",
                    valueMs = it,
                    bold = true,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Hardware: $securityHardware",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}

@Composable
private fun MetricRow(label: String, valueMs: Double, bold: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
        Text(
            text = "${valueMs.toLong()} ms",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
    }
}