package com.sofamsg.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * QR Code Scanner Screen — scans another user's QR code to add them
 * as a contact.
 *
 * The QR code contains the peer's `sb_`-prefixed account ID. Once
 * scanned, the app:
 *   1. Validates the account ID format
 *   2. Initiates an X3DH key exchange via the P2P layer
 *   3. Creates a new conversation entry in the local database
 *   4. Navigates to the chat screen
 *
 * Camera permission is requested at runtime via the standard Android
 * permission flow. If denied, a manual entry fallback is shown.
 *
 * @param onContactAdded Called with the scanned account ID on success
 * @param onBack Navigate back to the previous screen
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanQrScreen(
    onContactAdded: (accountId: String) -> Unit,
    onBack: () -> Unit
) {
    var manualId by remember { mutableStateOf("") }
    var isManualEntry by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Add Contact",
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (!isManualEntry) {
                // ── Camera viewfinder placeholder ──
                // TODO: Integrate CameraX + ML Kit barcode scanning
                Spacer(modifier = Modifier.height(32.dp))

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1f),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                imageVector = Icons.Default.CameraAlt,
                                contentDescription = "Camera",
                                modifier = Modifier.size(64.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "Point camera at a SofaMsg QR code",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "Camera integration pending CameraX setup",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ── Manual entry fallback ──
                OutlinedButton(
                    onClick = { isManualEntry = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Enter account ID manually")
                }
            } else {
                // ── Manual account ID entry ──
                Spacer(modifier = Modifier.height(32.dp))

                Text(
                    text = "Enter their Account ID",
                    style = MaterialTheme.typography.titleMedium
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Ask your contact for their sb_ account ID",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(24.dp))

                OutlinedTextField(
                    value = manualId,
                    onValueChange = {
                        manualId = it
                        errorMessage = null
                    },
                    label = { Text("Account ID") },
                    placeholder = { Text("sb_...") },
                    singleLine = true,
                    isError = errorMessage != null,
                    supportingText = errorMessage?.let { { Text(it) } },
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = {
                        if (manualId.startsWith("sb_") && manualId.length > 10) {
                            onContactAdded(manualId)
                        } else {
                            errorMessage = "Invalid account ID (must start with sb_)"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = manualId.isNotBlank()
                ) {
                    Text("Add Contact")
                }

                Spacer(modifier = Modifier.height(16.dp))

                TextButton(
                    onClick = { isManualEntry = false }
                ) {
                    Text("Back to QR scanner")
                }
            }
        }
    }
}
