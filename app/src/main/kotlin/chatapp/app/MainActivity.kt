package chatapp.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text

/**
 * Phase 5 spike — single-activity host. FLAG_SECURE is applied here per design §12
 * (unconditional from day one so it is never forgotten behind a feature toggle);
 * real navigation replaces the placeholder text in step 3.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            Text("ChatApp — Phase 5")
        }
    }
}
