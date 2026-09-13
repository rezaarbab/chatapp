package chatapp.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import chatapp.app.vm.ChatViewModel

/** Phase 5 (design §5) — real chat screen: mirror + outbox merge, send states. */
@Composable
fun ChatScreen(
    vm: ChatViewModel,
    title: String,
    onBack: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    var input by remember { mutableStateOf(TextFieldValue("")) }
    val listState = rememberLazyListState()

    LaunchedEffect(state.items.size) {
        if (state.items.isNotEmpty()) listState.animateScrollToItem(state.items.size - 1)
    }

    Column(Modifier.fillMaxSize().imePadding()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("بازگشت") }
            Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
        }
        if (state.banner != null) {
            Text(
                state.banner!!,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(horizontal = 16.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Box(Modifier.weight(1f)) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(state.items, key = { it.id }) { item ->
                    MessageBubble(item, onRetry = { vm.retry(item.id) })
                }
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("پیام…") },
                maxLines = 4,
            )
            TextButton(
                onClick = {
                    vm.send(input.text)
                    input = TextFieldValue("")
                },
                enabled = !state.sending && input.text.isNotBlank(),
            ) {
                if (state.sending) {
                    CircularProgressIndicator(Modifier.padding(4.dp))
                } else {
                    Text("ارسال")
                }
            }
        }
    }
}

@Composable
private fun MessageBubble(item: ConversationRepository.ThreadItem, onRetry: () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    Box(
        Modifier.fillMaxWidth(),
        contentAlignment = if (item.mine) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Surface(
            color = if (item.mine) MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
            shape = shape,
        ) {
            Column(Modifier.padding(10.dp)) {
                Text(item.text, style = MaterialTheme.typography.bodyLarge)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        formatTime(item.at),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    when (item.sendState) {
                        "pending" -> Text(" · در حال ارسال", style = MaterialTheme.typography.labelSmall)
                        "failed" -> TextButton(onClick = onRetry) {
                            Text("ارسال مجدد", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
}
