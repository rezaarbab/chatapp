package chatapp.app.e2e

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import chatapp.android.account.AccountManager
import chatapp.android.protocol.Messaging
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 5 acceptance (design §13): the MANDATE journey as ONE continuous
 * scenario on the real emulator against real staging, driving the REAL app:
 *
 *   install -> register (UI) -> open conversation (UI) -> send (UI)
 *   -> counterpart receives (real backend) -> counterpart replies
 *   -> UI receives -> relaunch -> history persists
 *
 * One sequential test keeps the registration budget at 2 (app + counterpart)
 * and mirrors how a real user uses the app. No plaintext/secret is ever
 * logged (Phase-4 rule #6).
 */
@RunWith(AndroidJUnit4::class)
class Phase5AcceptanceTest {

    @get:Rule
    val compose = createAndroidComposeRule<chatapp.app.MainActivity>()

    private lateinit var cp: CounterpartDevice

    @Before
    fun setUp() {
        cp = CounterpartDevice("acceptance")
        cp.openFresh()
        compose.waitForIdle()
    }

    @After
    fun tearDown() {
        cp.close()
    }

    private fun settle() {
        compose.waitForIdle()
        Thread.sleep(500)
    }

    private fun eventually(timeoutMs: Long = 30_000, check: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            settle()
            if (runCatching(check).getOrDefault(false)) return true
            Thread.sleep(700)
        }
        return false
    }

    private fun textVisible(t: String): Boolean = try {
        compose.onNodeWithText(t, substring = true).assertIsDisplayed()
        true
    } catch (_: Throwable) {
        false
    }

    private fun clickIfVisible(t: String, timeoutMs: Long = 20_000): Boolean {
        if (!eventually(timeoutMs) { textVisible(t) }) return false
        return try {
            compose.onNodeWithText(t, substring = true).performClick()
            true
        } catch (_: Throwable) {
            try {
                compose.onNodeWithText(t).performClick()
                true
            } catch (_: Throwable) { false }
        }
    }

    @Test
    fun fullJourney_register_send_receive_relaunch_persistence() {
        val cpUsername = AccountManager.randomUsername("cp")

        // ---------- 1. counterpart registers (outside the UI) ----------
        val cpState = cp.accounts.register(cpUsername)
        cp.preKeys.uploadBatch()

        // ---------- 2. app registers through the REAL UI (first run only) ----------
        if (eventually(15_000) { textVisible("ایجاد حساب جدید") }) {
            compose.onNodeWithText("ایجاد حساب جدید").performClick()
            settle()
            val appUsername = AccountManager.randomUsername("ui")
            compose.onNodeWithText("نام کاربری (a-z, 0-9, _, -)").performTextInput(appUsername)
            settle()
            compose.onNodeWithText("ثبت‌نام").performClick()
            assertTrue(
                "must reach home after UI register",
                eventually(120_000) { textVisible("گفتگوی جدید") },
            )
        } else {
            // A previous partial run already registered the app; continue.
            assertTrue(eventually { textVisible("گفتگوی جدید") })
        }

        // ---------- 3. open a new chat with the counterpart (account_id) ----------
        assertTrue("new chat button", clickIfVisible("گفتگوی جدید"))
        settle()
        compose.onNodeWithText("شناسه حساب (account_id)").performTextInput(cpState.accountId)
        settle()
        assertTrue("start chat", clickIfVisible("شروع"))
        settle()
        // the chat screen must be reachable before typing
        assertTrue(
            "chat screen must open (input visible)",
            eventually(30_000) { textVisible("پیام…") },
        )

        // ---------- 4. send from the UI ----------
        val outgoing = "salam az ui"
        compose.onNodeWithText("پیام…").performTextInput(outgoing)
        settle()
        assertTrue("send button", clickIfVisible("ارسال"))
        assertTrue(
            "bubble shows the sent text",
            eventually(60_000) { textVisible(outgoing) },
        )

        // ---------- 5. counterpart receives via the real backend ----------
        val received = mutableListOf<ByteArray>()
        var senderAccountId: String? = null
        var senderDevNo: Int? = null
        val deadline = System.currentTimeMillis() + 120_000
        while (received.isEmpty() && System.currentTimeMillis() < deadline) {
            cp.messaging.receive().forEach { msg ->
                if (!msg.duplicate) {
                    received.add(msg.plaintext)
                    senderAccountId = msg.senderAccountId
                    senderDevNo = msg.senderDevNo
                }
            }
        }
        assertTrue("counterpart must receive the UI message", received.isNotEmpty())
        assertTrue(
            "plaintext must match what the UI sent",
            received.any { String(it, Charsets.UTF_8) == outgoing },
        )

        // ---------- 6. counterpart replies; the UI must show it ----------
        val reply = "javab az counterpart"
        val appDevice = cp.messaging
            .discoverDevices(senderAccountId!!)
            .first { it.devNo == senderDevNo }
        cp.messaging.send(
            cp.preKeys,
            reply.toByteArray(Charsets.UTF_8),
            listOf(Messaging.TargetDevice(senderAccountId!!, appDevice.deviceId, appDevice.devNo)),
        )
        assertTrue(
            "UI must show the counterpart reply after a sync",
            eventually(120_000) { textVisible(reply) },
        )

        // ---------- 7. relaunch; history + session persist ----------
        compose.activityRule.scenario.onActivity { it.recreate() }
        assertTrue("home after relaunch", eventually(30_000) { textVisible("گفتگوی جدید") })
        assertTrue("chat row persists", clickIfVisible(cpState.accountId, 30_000))
        assertTrue("sent message survives relaunch", eventually { textVisible(outgoing) })
        assertTrue("reply survives relaunch", eventually { textVisible(reply) })
    }
}
