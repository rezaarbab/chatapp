package chatapp.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import chatapp.android.repo.ConversationRepository
import chatapp.app.vm.ConversationsViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Phase 5 (design §4) — conversation list + new-chat + sync banner. */
@Composable
fun ConversationsScreen(
    vm: ConversationsViewModel,
    onOpenChat: (peerKey: String, title: String) -> Unit,
    onOpenDevices: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val newChatError by vm.newChatError.collectAsStateWithLifecycle()
    var showNewChat by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("گفتگوها", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = onOpenDevices) { Text("دستگاه‌ها") }
            TextButton(onClick = { showNewChat = true }) { Text("گفتگوی جدید") }
        }
        if (state.syncLabel.isNotBlank()) {
            Text(
                state.syncLabel,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.secondary,
            )
        }
        when {
            state.loading -> CircularProgressIndicator(Modifier.padding(32.dp))
            state.conversations.isEmpty() -> Text(
                "هنوز گفتگویی ندارید",
                modifier = Modifier.padding(24.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> LazyColumn(Modifier.fillMaxSize()) {
                items(state.conversations, key = { it.peerKey }) { conv ->
                    ConversationRow(conv, onOpenChat)
                    HorizontalDivider()
                }
            }
        }
    }

    if (showNewChat) {
        var username by remember { mutableStateOf(TextFieldValue("")) }
        AlertDialog(
            onDismissRequest = { showNewChat = false; vm.clearNewChatError() },
            title = { Text("گفتگوی جدید") },
            text = {
                Column {
                    Text(
                        "شناسه حساب گیرنده را وارد کنید (username-lookup روی سرور موجود نیست؛ پس از اولین پیام، نام نمایشی ذخیره می‌شود)",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = username,
                        onValueChange = { username = it },
                        label = { Text("شناسه حساب (account_id)") },
                        singleLine = true,
                    )
                    if (newChatError != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(newChatError!!, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    vm.startNewChat(username.text) { key ->
                        showNewChat = false
                        onOpenChat(key, username.text)
                    }
                }) { Text("شروع") }
            },
            dismissButton = {
                TextButton(onClick = { showNewChat = false; vm.clearNewChatError() }) { Text("انصراف") }
            },
        )
    }
}

@Composable
private fun ConversationRow(
    conv: ConversationRepository.Conversation,
    onOpenChat: (String, String) -> Unit,
) {
    Column(
        Modifier.fillMaxWidth()
            .clickable { onOpenChat(conv.peerKey, conv.peerUsername) }
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(conv.peerUsername, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            Text(formatTime(conv.lastActivityAt), style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                conv.previewSnippet.ifBlank { "…" },
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                modifier = Modifier.weight(1f),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(8.dp))
            when (conv.lastOutState) {
                "pending" -> Text("…", color = MaterialTheme.colorScheme.secondary)
                "failed" -> Text("!", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

internal fun formatTime(at: Long): String {
    val fmt = SimpleDateFormat("MM-dd HH:mm", Locale.ROOT)
    return fmt.format(Date(at))
}
