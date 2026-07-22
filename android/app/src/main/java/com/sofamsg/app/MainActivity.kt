package com.sofamsg.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.sofamsg.app.ui.ChatScreen
import com.sofamsg.app.ui.ConversationListScreen
import com.sofamsg.app.ui.PinEntryScreen
import com.sofamsg.app.ui.ScanQrScreen
import com.sofamsg.app.ui.SettingsScreen
import com.sofamsg.app.ui.theme.SofaMsgTheme

/**
 * Single Activity — the entire app UI is Jetpack Compose.
 *
 * Navigation flow:
 *   PIN entry → conversation list → chat / settings / QR scan
 *
 * Security measures:
 *   • FLAG_SECURE prevents screenshots and recent-apps thumbnails
 *   • PIN must be entered every time the app opens (no biometric bypass)
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Prevent screenshots and task-switcher preview.
        // This is critical for a privacy-focused messenger.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContent {
            SofaMsgTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()

                    // Track whether the user has authenticated this session
                    var isAuthenticated by remember { mutableStateOf(false) }

                    NavHost(
                        navController = navController,
                        startDestination = "pin_entry"
                    ) {
                        // ── PIN Entry (always first) ──
                        composable("pin_entry") {
                            PinEntryScreen(
                                onAuthenticated = { isDuress ->
                                    isAuthenticated = true
                                    // Both real and duress PINs navigate to
                                    // the conversation list — the duress path
                                    // shows decoy content instead of real data.
                                    navController.navigate("conversations") {
                                        popUpTo("pin_entry") { inclusive = true }
                                    }
                                }
                            )
                        }

                        // ── Conversation list ──
                        composable("conversations") {
                            ConversationListScreen(
                                onConversationClick = { peerId ->
                                    navController.navigate("chat/$peerId")
                                },
                                onSettingsClick = {
                                    navController.navigate("settings")
                                },
                                onScanQrClick = {
                                    navController.navigate("scan_qr")
                                }
                            )
                        }

                        // ── Individual chat ──
                        composable("chat/{peerId}") { backStackEntry ->
                            val peerId = backStackEntry.arguments
                                ?.getString("peerId") ?: ""
                            ChatScreen(
                                peerId = peerId,
                                onBack = { navController.popBackStack() }
                            )
                        }

                        // ── Settings ──
                        composable("settings") {
                            SettingsScreen(
                                onBack = { navController.popBackStack() }
                            )
                        }

                        // ── QR scanner ──
                        composable("scan_qr") {
                            ScanQrScreen(
                                onContactAdded = { accountId ->
                                    // Navigate to the new chat after scanning
                                    navController.navigate("chat/$accountId") {
                                        popUpTo("conversations")
                                    }
                                },
                                onBack = { navController.popBackStack() }
                            )
                        }
                    }
                }
            }
        }
    }
}
