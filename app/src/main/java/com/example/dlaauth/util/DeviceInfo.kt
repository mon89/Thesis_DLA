package com.example.dlaauth.util

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.example.dlaauth.model.DeviceSignals
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DeviceInfo {

    fun collectSignals(): DeviceSignals {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return DeviceSignals(
            userAgent = "${Build.MANUFACTURER} ${Build.MODEL}",
            platform = "Android",
            timezone = TimeZone.getDefault().id,
            osVersion = "Android ${Build.VERSION.RELEASE}",
            deviceModel = Build.MODEL,
            timestamp = sdf.format(Date()),
        )
    }

    fun isStrongBoxAvailable(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    fun isTEEAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

    fun deviceSummary(context: Context): String {
        val security = if (isStrongBoxAvailable(context)) "StrongBox" else "TEE"
        return "${Build.MODEL}, Android ${Build.VERSION.RELEASE}, $security"
    }
}