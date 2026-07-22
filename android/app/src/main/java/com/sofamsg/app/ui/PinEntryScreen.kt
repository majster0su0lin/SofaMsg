package com.sofamsg.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * PIN Entry Screen — the first thing the user sees on every app launch.
 *
 * Supports two PINs:
 *   • **Real PIN** — unlocks the genuine vault with real conversations
 *   • **Duress PIN** — unlocks a decoy vault with fake conversations
 *
 * From a UI perspective, both PINs behave identically — the user sees
 * a conversation list in both cases. The distinction is handled by the
 * vault layer (silentbell_core): different PINs derive different keys,
 * which decrypt different databases.
 *
 * @param onAuthenticated Called when PIN validation succeeds.
 *   The boolean parameter is `true` if the duress PIN was entered.
 *   (In the current skeleton this is always `false` — real PIN
 *   validation will be wired up when the vault FFI is integrated.)
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinEntryScreen(
    onAuthenticated: (isDuress: Boolean) -> Unit
) {
    var pin by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // ── App icon / lock icon ──
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = "Locked",
                modifier = Modifier.size(72.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(24.dp))

            // ── Title ──
            Text(
                text = "SofaMsg",
                style = MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.onBackground
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Enter your PIN to unlock",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            // ── PIN input field ──
            OutlinedTextField(
                value = pin,
                onValueChange = { newValue ->
                    // Only allow digits, max 8 characters
                    if (newValue.all { it.isDigit() } && newValue.length <= 8) {
                        pin = newValue
                        errorMessage = null
                    }
                },
                label = { Text("PIN") },
                placeholder = { Text("Enter 4–8 digit PIN") },
                singleLine = true,
                visualTransformation = if (pinVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = {
                        if (pin.length >= 4) {
                            attemptUnlock(pin, onAuthenticated) { error ->
                                errorMessage = error
                            }
                        }
                    }
                ),
                trailingIcon = {
                    IconButton(onClick = { pinVisible = !pinVisible }) {
                        Icon(
                            imageVector = if (pinVisible) {
                                Icons.Default.VisibilityOff
                            } else {
                                Icons.Default.Visibility
                            },
                            contentDescription = if (pinVisible) {
                                "Hide PIN"
                            } else {
                                "Show PIN"
                            }
                        )
                    }
                },
                isError = errorMessage != null,
                supportingText = errorMessage?.let { { Text(it) } },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(24.dp))

            // ── Unlock button ──
            val context = androidx.compose.ui.platform.LocalContext.current
            Button(
                onClick = {
                    if (pin.length >= 4) {
                        attemptUnlock(context, pin, onAuthenticated) { error ->
                            errorMessage = error
                        }
                    } else {
                        errorMessage = "PIN must be at least 4 digits"
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                enabled = pin.length >= 4 && !isLoading
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Unlock")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ── Subtle hint about duress PIN ──
            // Intentionally vague — a coercer shouldn't know this exists
            Text(
                text = "Forgot your PIN? There is no recovery.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                textAlign = TextAlign.Center
            )
        }
    }
}

/**
 * Attempt to unlock the vault with the given PIN via silentbell_core.
 */
private fun attemptUnlock(
    context: android.content.Context,
    pin: String,
    onAuthenticated: (isDuress: Boolean) -> Unit,
    onError: (String) -> Unit
) {
    if (pin.length < 4) {
        onError("PIN must be at least 4 digits")
        return
    }
    // Duress PIN detection (convention: PINs ending in '9999' or explicit '9999')
    val isDuress = (pin == "9999")
    val coreManager = com.sofamsg.app.core.SofaMsgCoreManager(context)
    val success = coreManager.unlock(pin, isDuress)
    if (success) {
        onAuthenticated(isDuress)
    } else {
        onError("Failed to unlock vault")
    }
}
