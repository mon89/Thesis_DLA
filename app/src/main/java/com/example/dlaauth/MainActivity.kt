package com.example.dlaauth

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.example.dlaauth.service.DLAAuthManager
import com.example.dlaauth.ui.DLAApp
import com.example.dlaauth.ui.theme.DLAAuthTheme

class MainActivity : ComponentActivity() {

    private val authManager: DLAAuthManager by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        authManager.setActivity(this)
        enableEdgeToEdge()
        setContent {
            DLAAuthTheme {
                DLAApp(authManager = authManager)
            }
        }
    }
}