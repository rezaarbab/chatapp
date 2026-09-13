package chatapp.app

import org.junit.Assert.assertEquals
import org.junit.Test

/** Spike smoke: JVM unit test execution inside :app is wired. */
class SpikeUnitTest {
    @Test
    fun moduleBuilds() {
        assertEquals("ChatApp — Phase 5", "ChatApp — Phase 5")
    }
}
