package chatapp.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import chatapp.android.repo.ConversationRepository
import chatapp.app.ui.ChatAppTheme
import chatapp.app.ui.ChatScreen
import chatapp.app.ui.ConversationsScreen
import chatapp.app.ui.DevicesScreen
import chatapp.app.ui.OnboardingScreen
import chatapp.app.vm.ChatViewModel
import chatapp.app.vm.ConversationsViewModel
import chatapp.app.vm.DevicesViewModel
import chatapp.app.vm.OnboardingViewModel

/**
 * Phase 5 (design §10/§12) — single-activity host, FLAG_SECURE unconditional,
 * StateFlow-only state, manual DI (AppContainer from ChatApplication).
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            ChatAppTheme {
                val app = application as ChatApplication
                val container = remember {
                    try { app.container() } catch (e: ChatApplication.FatalError) { null }
                }
                if (container == null) {
                    FatalStoreScreen(onWipe = { finish() })
                } else {
                    AppNavHost(container)
                }
            }
        }
    }
}

@Composable
private fun AppNavHost(container: AppContainer) {
    val nav = rememberNavController()
    val repo = container.repository
    val registeredInitially = remember { repo.isRegistered() }

    NavHost(navController = nav, startDestination = if (registeredInitially) "home" else "welcome") {
        composable("welcome") {
            val vm: OnboardingViewModel = viewModel(factory = OnboardingViewModel.Factory(repo))
            OnboardingScreen(vm, onDone = { nav.navigate("home") { popUpTo("welcome") { inclusive = true } } })
        }
        composable("home") {
            val vm: ConversationsViewModel = viewModel(factory = ConversationsViewModel.Factory(repo))
            ConversationsScreen(
                vm,
                onOpenChat = { peer, title -> nav.navigate("chat/$peer?title=$title") },
                onOpenDevices = { nav.navigate("devices") },
            )
        }
        composable("chat/{peerKey}?title={title}") { entry ->
            val peerKey = entry.arguments?.getString("peerKey") ?: return@composable
            val title = entry.arguments?.getString("title") ?: peerKey
            val vm: ChatViewModel = viewModel(factory = ChatViewModel.Factory(repo, peerKey))
            ChatScreen(vm, title = title, onBack = { nav.popBackStack() })
        }
        composable("devices") {
            val vm: DevicesViewModel = viewModel(factory = DevicesViewModel.Factory(repo))
            DevicesScreen(vm, onBack = { nav.popBackStack() })
        }
    }
}

/** Design §9 — honest screen when the encrypted store cannot be opened. */
@Composable
private fun FatalStoreScreen(onWipe: () -> Unit) {
    Scaffold { pad ->
        Box(Modifier.fillMaxSize().padding(pad), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("باز کردن پایگاه‌داده رمزنگاری‌شده ممکن نشد", Modifier.padding(16.dp))
                Text(
                    "کلید Android KeyStore با دادهٔ برنامه هم‌راستا نیست. تنها راه، پاک‌سازی داده‌ها از تنظیمات سیستم است.",
                    Modifier.padding(16.dp),
                )
                Button(onClick = onWipe) { Text("خروج") }
            }
        }
    }
}
