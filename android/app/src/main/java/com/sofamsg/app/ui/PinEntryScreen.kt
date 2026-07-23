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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * PIN Entry & Setup Screen — shown on app launch.
 *
 * Handles two states:
 *   1. **Setup Mode** (First launch / no PIN set): Prompts user to create
 *      and confirm a 4–8 digit PIN before initializing the vault.
 *   2. **Unlock Mode** (PIN set): Prompts user to enter their PIN to unlock.
 *
 * Supports two PINs in Unlock Mode:
 *   • **Real PIN** — unlocks the genuine vault with real conversations
 *   • **Duress PIN** — unlocks a decoy vault with fake conversations
 *
 * **Safe Fallback**: If the screen is launched in Unlock Mode but no PIN is
 * configured, it automatically switches to Setup Mode so the user is never
 * locked out.
 *
 * All PIN derivation (Argon2id) and database initialization operations run on
 * Dispatchers.IO to prevent main thread looper stalls.
 *
 * @param onAuthenticated Called when PIN validation or setup succeeds.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinEntryScreen(
    onAuthenticated: (isDuress: Boolean) -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val coreManager = remember { com.sofamsg.app.core.SofaMsgCoreManager(context) }

    // Check whether a PIN has been set
    var isSetupMode by remember { mutableStateOf(!coreManager.isPinSet()) }
    var isConfirmStep by remember { mutableStateOf(false) }
    var initialPin by remember { mutableStateOf("") }

    var pin by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    // Safe fallback: if shown in unlock mode when no PIN exists, switch to setup
    LaunchedEffect(Unit) {
        if (!isSetupMode && !coreManager.isPinSet()) {
            isSetupMode = true
        }
    }

    val titleText = when {
        isSetupMode && !isConfirmStep -> "Create your PIN"
        isSetupMode && isConfirmStep -> "Confirm your PIN"
        else -> "SofaMsg"
    }

    val subtitleText = when {
        isSetupMode && !isConfirmStep -> "Set a 4–8 digit PIN to protect your vault"
        isSetupMode && isConfirmStep -> "Re-enter your PIN to confirm"
        else -> "Enter your PIN to unlock"
    }

    val buttonText = when {
        isSetupMode && !isConfirmStep -> "Next"
        isSetupMode && isConfirmStep -> "Create PIN"
        else -> "Unlock"
    }

    val submitAction: () -> Unit = {
        if (isLoading) return@submitAction

        if (pin.length < 4) {
            errorMessage = "PIN must be at least 4 digits"
        } else if (isSetupMode) {
            if (!isConfirmStep) {
                // First step of setup — save initial PIN and ask for confirmation
                initialPin = pin
                pin = ""
                isConfirmStep = true
                errorMessage = null
            } else {
                // Second step of setup — confirm matching PIN
                if (pin == initialPin) {
                    val confirmedPin = pin
                    isLoading = true
                    errorMessage = null
                    coroutineScope.launch {
                        try {
                            val success = withContext(Dispatchers.IO) {
                                coreManager.setupPin(confirmedPin)
                            }
                            withContext(Dispatchers.Main) {
                                if (success) {
                                    onAuthenticated(false)
                                } else {
                                    isLoading = false
                                    errorMessage = "Failed to initialize vault database"
                                }
                            }
                        } catch (e: Throwable) {
                            withContext(Dispatchers.Main) {
                                isLoading = false
                                errorMessage = "Error initializing vault: ${e.message}"
                            }
                        }
                    }
                } else {
                    errorMessage = "PINs do not match. Try again."
                    pin = ""
                    initialPin = ""
                    isConfirmStep = false
                }
            }
        } else {
            // Unlock mode with safe fallback
            if (!coreManager.isPinSet()) {
                isSetupMode = true
                isConfirmStep = false
                pin = ""
                errorMessage = "No PIN configured. Create a new PIN."
            } else {
                val enteredPin = pin
                isLoading = true
                errorMessage = null
                coroutineScope.launch {
                    try {
                        val isDuress = (enteredPin == "9999")
                        val success = withContext(Dispatchers.IO) {
                            coreManager.unlock(enteredPin, isDuress)
                        }
                        withContext(Dispatchers.Main) {
                            if (success) {
                                onAuthenticated(isDuress)
                            } else {
                                isLoading = false
                                errorMessage = "Failed to unlock vault. Incorrect PIN."
                            }
                        }
                    } catch (e: Throwable) {
                        withContext(Dispatchers.Main) {
                            isLoading = false
                            errorMessage = "Unlock error: ${e.message}"
                        }
                    }
                }
            }
        }
    }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // ── Lock icon ──
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = "Locked",
                modifier = Modifier.size(72.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(24.dp))

            // ── Title ──
            Text(
                text = titleText,
                style = MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.onBackground
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = subtitleText,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            // ── PIN input field ──
            OutlinedTextField(
                value = pin,
                onValueChange = { newValue ->
                    if (newValue.all { it.isDigit() } && newValue.length <= 8) {
                        pin = newValue
                        errorMessage = null
                    }
                },
                label = { Text("PIN") },
                placeholder = {
                    Text(if (isConfirmStep) "Re-enter PIN" else "Enter 4–8 digit PIN")
                },
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
                    onDone = { submitAction() }
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

            // ── Action button ──
            Button(
                onClick = submitAction,
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
                    Text(buttonText)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ── Footer text / recovery note ──
            Text(
                text = if (isSetupMode) {
                    "Your PIN cannot be recovered if forgotten."
                } else {
                    "Forgot your PIN? There is no recovery."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                textAlign = TextAlign.Center
            )
        }
    }
}
