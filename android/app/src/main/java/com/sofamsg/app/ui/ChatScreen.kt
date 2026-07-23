package com.sofamsg.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Chat Screen — individual conversation with a peer.
 *
 * Messages are end-to-end encrypted via the Double Ratchet protocol
 * (Layer 0 encryption using AES-256-GCM). The vault layer (Layer 1,
 * AES-256-CBC without auth tag) provides at-rest encryption with
 * deniability.
 *
 * @param peerId The `sb_`-prefixed account ID of the conversation peer
 * @param onBack Navigate back to conversation list
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    peerId: String,
    onBack: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val coreManager = remember { com.sofamsg.app.core.SofaMsgCoreManager(context) }
    var messageText by remember { mutableStateOf("") }
    var refreshCounter by remember { mutableStateOf(0) }
    val storedMsgs = remember(peerId, refreshCounter) { coreManager.getMessages(peerId) }

    val messages = remember(storedMsgs) {
        if (storedMsgs.isNotEmpty()) {
            storedMsgs.map { m ->
                ChatMessage(
                    id = m.id,
                    body = m.body,
                    isOutgoing = m.isOutgoing,
                    timestamp = java.text.SimpleDateFormat("h:mm a", java.util.Locale.getDefault())
                        .format(java.util.Date(m.sentAt * 1000))
                )
            }
        } else {
            listOf(
                ChatMessage(
                    id = 1,
                    body = "This chat is secured with multi-layer encryption. Messages are saved to your local vault.",
                    isOutgoing = false,
                    timestamp = "System"
                )
            )
        }
    }

    val listState = rememberLazyListState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            // TODO: Show peer display name instead of raw ID
                            text = peerId.take(16) + "…",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "End-to-end encrypted",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
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
        },
        bottomBar = {
            // ── Message input bar ──
            Surface(
                tonalElevation = 3.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .padding(horizontal = 8.dp, vertical = 8.dp)
                        .imePadding(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = messageText,
                        onValueChange = { messageText = it },
                        placeholder = { Text("Message") },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(24.dp),
                        maxLines = 4
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    FilledIconButton(
                        onClick = {
                            if (messageText.isNotBlank()) {
                                coreManager.saveMessage(peerId, messageText.trim(), true)
                                messageText = ""
                                refreshCounter++
                            }
                        },
                        enabled = messageText.isNotBlank()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Send,
                            contentDescription = "Send"
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        // ── Message list ──
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 8.dp),
            state = listState,
            verticalArrangement = Arrangement.spacedBy(4.dp),
            contentPadding = PaddingValues(vertical = 8.dp)
        ) {
            items(messages) { message ->
                MessageBubble(message = message)
            }
        }
    }
}

/**
 * A single message bubble — outgoing messages on the right (primary color),
 * incoming messages on the left (surface variant color).
 */
@Composable
private fun MessageBubble(message: ChatMessage) {
    val isOutgoing = message.isOutgoing
    val bubbleColor = if (isOutgoing) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val textColor = if (isOutgoing) {
        MaterialTheme.colorScheme.onPrimary
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    val alignment = if (isOutgoing) Alignment.End else Alignment.Start
    val shape = if (isOutgoing) {
        RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp)
    } else {
        RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp)
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = alignment
    ) {
        Surface(
            shape = shape,
            color = bubbleColor,
            modifier = Modifier.widthIn(max = 280.dp)
        ) {
            Column(
                modifier = Modifier.padding(
                    horizontal = 12.dp,
                    vertical = 8.dp
                )
            ) {
                Text(
                    text = message.body,
                    color = textColor,
                    style = MaterialTheme.typography.bodyLarge
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = message.timestamp,
                    color = textColor.copy(alpha = 0.7f),
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }
}

/**
 * Data class for chat messages.
 * Will be replaced by data from SQLCipher once FFI is wired up.
 */
data class ChatMessage(
    val id: Long,
    val body: String,
    val isOutgoing: Boolean,
    val timestamp: String
)
