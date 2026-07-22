package com.sofamsg.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * Conversation List Screen — shows all active conversations.
 *
 * In the real vault this displays actual encrypted conversations;
 * in the duress vault this displays decoy conversations generated
 * by silentbell_core::generate_decoy_content.
 *
 * Both look identical from a UI perspective — this is the core of
 * the plausible deniability feature.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationListScreen(
    onConversationClick: (peerId: String) -> Unit,
    onSettingsClick: () -> Unit,
    onScanQrClick: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val coreManager = remember { com.sofamsg.app.core.SofaMsgCoreManager(context) }
    val storedConvos = remember { coreManager.getRecentConversations() }

    val conversations = remember(storedConvos) {
        if (storedConvos.isNotEmpty()) {
            storedConvos.map { msg ->
                ConversationPreview(
                    peerId = msg.peerAccountId,
                    peerName = msg.peerAccountId.take(12) + "...",
                    lastMessage = msg.body,
                    timestamp = "Recent",
                    unreadCount = 0
                )
            }
        } else {
            listOf(
                ConversationPreview(
                    peerId = "sb_demo_peer",
                    peerName = "Alice",
                    lastMessage = "Welcome to SofaMsg! Tap QR icon to scan a contact.",
                    timestamp = "Just now",
                    unreadCount = 0
                )
            )
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "SofaMsg",
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    // QR scanner button — for adding new contacts
                    IconButton(onClick = onScanQrClick) {
                        Icon(
                            imageVector = Icons.Default.QrCodeScanner,
                            contentDescription = "Scan QR code"
                        )
                    }
                    // Settings button
                    IconButton(onClick = onSettingsClick) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onScanQrClick,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = "New conversation"
                )
            }
        }
    ) { innerPadding ->
        if (conversations.isEmpty()) {
            // ── Empty state ──
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "No conversations yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Scan a QR code to add a contact",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                }
            }
        } else {
            // ── Conversation list ──
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                items(conversations) { conversation ->
                    ConversationItem(
                        conversation = conversation,
                        onClick = { onConversationClick(conversation.peerId) }
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(start = 72.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f)
                    )
                }
            }
        }
    }
}

/**
 * A single conversation row in the list.
 */
@Composable
private fun ConversationItem(
    conversation: ConversationPreview,
    onClick: () -> Unit
) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        headlineContent = {
            Text(
                text = conversation.peerName,
                fontWeight = FontWeight.SemiBold
            )
        },
        supportingContent = {
            Text(
                text = conversation.lastMessage,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        },
        trailingContent = {
            Column(
                horizontalAlignment = Alignment.End
            ) {
                Text(
                    text = conversation.timestamp,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (conversation.unreadCount > 0) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Badge {
                        Text(conversation.unreadCount.toString())
                    }
                }
            }
        },
        leadingContent = {
            // Avatar placeholder — first letter of name in a circle
            Surface(
                modifier = Modifier.size(48.dp),
                shape = MaterialTheme.shapes.extraLarge,
                color = MaterialTheme.colorScheme.primaryContainer
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        text = conversation.peerName.first().toString(),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }
        }
    )
}

/**
 * Data class for conversation list items.
 * Will be replaced by actual data from SQLCipher once FFI is wired up.
 */
data class ConversationPreview(
    val peerId: String,
    val peerName: String,
    val lastMessage: String,
    val timestamp: String,
    val unreadCount: Int
)
