package chatapp.app

import android.app.Application

/**
 * Phase 5 spike — application entry point. Full runtime wiring (ClientRuntime,
 * repository, poller) lands in step 3 per the approved plan; the spike proves
 * module wiring, dependency resolution, and CI build first.
 */
class ChatApplication : Application()
