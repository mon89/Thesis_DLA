package com.example.dlaauth.util

import android.util.Log

object LatencyLogger {

    @PublishedApi internal const val TAG = "LATENCY"
    @PublishedApi internal val measurements = mutableMapOf<String, Double>()

    inline fun <T> measure(label: String, block: () -> T): Pair<T, Double> {
        val start = System.nanoTime()
        val result = block()
        val elapsedMs = (System.nanoTime() - start) / 1_000_000.0
        Log.d(TAG, "$label: ${"%.2f".format(elapsedMs)}ms")
        measurements[label] = elapsedMs
        return Pair(result, elapsedMs)
    }

    fun summary(): String = buildString {
        appendLine("=== Latency Summary ===")
        measurements.forEach { (label, ms) ->
            appendLine("  $label: ${"%.2f".format(ms)}ms")
        }
        val total = measurements.values.sum()
        appendLine("  TOTAL: ${"%.2f".format(total)}ms")
    }

    fun reset() {
        measurements.clear()
    }
}