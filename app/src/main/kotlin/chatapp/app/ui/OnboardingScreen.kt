package chatapp.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import chatapp.app.vm.OnboardingViewModel

/**
 * Phase 5 (design §3) — welcome / register / add-device. Persian MVP strings.
 * No secret ever rendered: errors carry server status codes and user text only.
 */
@Composable
fun OnboardingScreen(
    vm: OnboardingViewModel,
    onDone: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()

    LaunchedEffect(state) {
        if (state is OnboardingViewModel.State.Done) onDone()
    }

    when (val s = state) {
        is OnboardingViewModel.State.Choose -> Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text("ChatApp", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text("پیام‌رسان رمزنگاری‌شده", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(32.dp))
            Button(onClick = vm::chooseRegister, modifier = Modifier.fillMaxWidth()) {
                Text("ایجاد حساب جدید")
            }
            Spacer(Modifier.height(12.dp))
            OutlinedButton(onClick = vm::chooseAddDevice, modifier = Modifier.fillMaxWidth()) {
                Text("افزودن این دستگاه به حساب موجود")
            }
        }

        is OnboardingViewModel.State.RegisterForm -> {
            var username by remember { mutableStateOf(TextFieldValue("")) }
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
            ) {
                Text("انتخاب نام کاربری", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("نام کاربری (a-z, 0-9, _, -)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { vm.register(username.text) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = username.text.isNotBlank(),
                ) { Text("ثبت‌نام") }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = vm::back, modifier = Modifier.fillMaxWidth()) {
                    Text("بازگشت")
                }
            }
        }

        is OnboardingViewModel.State.AddDeviceForm -> {
            var username by remember { mutableStateOf(TextFieldValue("")) }
            var accountId by remember { mutableStateOf(TextFieldValue("")) }
            var authorizer by remember { mutableStateOf(TextFieldValue("")) }
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
            ) {
                Text("افزودن دستگاه", style = MaterialTheme.typography.titleLarge)
                Text(
                    "روی دستگاه مجازدهنده، شناسه دستگاه را از تب «دستگاه‌ها» کپی کنید",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("نام کاربری حساب") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = accountId,
                    onValueChange = { accountId = it },
                    label = { Text("شناسه حساب (account_id)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = authorizer,
                    onValueChange = { authorizer = it },
                    label = { Text("شناسه دستگاه مجازدهنده") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { vm.addDevice(username.text, accountId.text, authorizer.text) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = username.text.isNotBlank() && accountId.text.isNotBlank() && authorizer.text.isNotBlank(),
                ) { Text("پیوستن به حساب") }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = vm::back, modifier = Modifier.fillMaxWidth()) {
                    Text("بازگشت")
                }
            }
        }

        is OnboardingViewModel.State.Working -> Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
        ) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text("در حال انجام…")
        }

        is OnboardingViewModel.State.Failure -> Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(s.message, color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(16.dp))
            if (s.retryable) {
                Button(onClick = vm::retry, modifier = Modifier.fillMaxWidth()) { Text("تلاش مجدد") }
            } else {
                OutlinedButton(onClick = vm::retry, modifier = Modifier.fillMaxWidth()) { Text("بازگشت") }
            }
        }

        is OnboardingViewModel.State.Done -> {}
    }
}
