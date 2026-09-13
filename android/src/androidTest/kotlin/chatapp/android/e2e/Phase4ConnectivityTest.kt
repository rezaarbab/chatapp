package chatapp.android.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import chatapp.android.net.ChatApiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
/**
 * Phase 4 / T0 (user mandate step 1): proves the REAL emulator reaches the REAL
 * Cloudflare staging deployment before anything else is built or trusted.
 *
 * Assertions are the exact server contract (Phase 1/3): an unauthenticated
 * `GET /devices/me` answers 401 UNAUTHORIZED and echoes the correlation id.
 * If the emulator cannot reach workers.dev at all, this test fails with the
 * underlying transport exception as evidence — and per the user mandate the
 * phase stops there (no speculative workarounds).
 */
@RunWith(AndroidJUnit4::class)
class Phase4ConnectivityTest {

    private val stagingUrl: String = requireNotNull(
        InstrumentationRegistry.getArguments().getString("stagingUrl"),
    ) { "stagingUrl instrumentation argument missing" }

    @Test
    fun t0_emulatorReachesRealStagingAndAuthWallIsActive() {
        val client = ChatApiClient(stagingUrl)
        try {
            client.request("GET", "/devices/me")
            fail("expected 401 from the staging auth wall")
        } catch (e: ChatApiClient.ApiException) {
            assertEquals("unexpected status from staging", 401, e.status)
            assertEquals("unexpected error code from staging", "UNAUTHORIZED", e.code)
            assertNotNull("staging must echo x-correlation-id", e.correlationId)
        }
    }
}
