package chatapp.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import chatapp.android.repo.ConversationRepository
import chatapp.app.vm.DevicesViewModel

/**
 * Phase 5 (design §11) — device list + revoke (typed confirmation for self)
 * + own device id display (authorizer side of add_device).
 */
@Composable
fun DevicesScreen(vm: DevicesViewModel, onBack: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    var revokeTarget by remember { mutableStateOf<ConversationRepository.DeviceRow?>(null) }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("بازگشت") }
            Text("دستگاه‌های من", style = MaterialTheme.typography.titleMedium)
        }
        if (state.banner != null) {
            Text(
                state.banner!!,
                modifier = Modifier.padding(horizontal = 16.dp),
                color = if (state.banner == "دستگاه حذف شد") MaterialTheme.colorScheme.secondary
                else MaterialTheme.colorScheme.error,
            )
        }
        Text(
            "شناسه این دستگاه (برای افزودن دستگاه جدید کپی کنید):",
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(16.dp),
        )
        Text(
            state.myDeviceId,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        Spacer(Modifier.height(8.dp))
        when {
            state.loading -> CircularProgressIndicator(Modifier.padding(32.dp))
            else -> LazyColumn(Modifier.fillMaxSize()) {
                items(state.devices, key = { it.deviceId }) { d ->
                    DeviceRow(d, onRevoke = { revokeTarget = d })
                    HorizontalDivider()
                }
            }
        }
    }

    revokeTarget?.let { target ->
        val isSelf = target.deviceId == state.myDeviceId
        AlertDialog(
            onDismissRequest = { revokeTarget = null },
            title = { Text(if (isSelf) "حذف همین دستگاه؟" else "حذف دستگاه #${target.devNo}؟") },
            text = {
                Text(
                    if (isSelf)
                        "این کار این دستگاه را برای همیشه از حساب حذف می‌کند و بدون افزودن مجدد، غیرقابل بازگشت است."
                    else
                        "دستگاه حذف‌شده دیگر به حساب دسترسی ندارد. مطمئنید؟",
                )
            },
            confirmButton = {
                Button(onClick = {
                    vm.revoke(target.deviceId, confirmed = true)
                    revokeTarget = null
                }) { Text("حذف") }
            },
            dismissButton = {
                OutlinedButton(onClick = { revokeTarget = null }) { Text("انصراف") }
            },
        )
    }
}

@Composable
private fun DeviceRow(d: ConversationRepository.DeviceRow, onRevoke: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("دستگاه #${d.devNo}", style = MaterialTheme.typography.titleMedium)
            if (d.thisDevice) {
                Text(
                    "این دستگاه",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        if (!d.thisDevice) {
            TextButton(onClick = onRevoke) { Text("حذف") }
        }
    }
}
