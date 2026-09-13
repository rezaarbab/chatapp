plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "chatapp.app"
    // Route B (user-approved): BOM 2026.08.00 (compose 1.10.x) requires compileSdk 36
    // and AGP >= 8.9.1; AGP is 8.13.2 (root build.gradle.kts). :android stays on 35.
    compileSdk = 36

    defaultConfig {
        applicationId = "chatapp.app"
        minSdk = 26
        targetSdk = 35 // runtime behavior unchanged; only compileSdk moved for BOM 2026.08.00
        versionCode = 1
        versionName = "0.1.0"
        // Same public staging default as :android (overridable via -PstagingUrl)
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["stagingUrl"] =
            (project.findProperty("stagingUrl") as String?) ?: "https://chatapp-staging.aacc32351.workers.dev"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // libsignal-android (via :android) requires core library desugaring
        isCoreLibraryDesugaringEnabled = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false // MVP; no proguard surface yet
        }
    }

    packaging {
        resources {
            // Desktop natives pulled transitively from libsignal must not ship
            excludes += setOf("libsignal_jni*.dylib", "signal_jni*.dll", "libsignal_jni_testing.so")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    implementation(project(":android"))

    // --- Phase 5 UI stack (PHASE5_APP_DESIGN.md §2; BOM corrected per CI evidence:
    // BOM 2026.08.00 pins compose 1.12.0 which requires compileSdk 37 + AGP 9.1.0 —
    // outside the approved route-B envelope. BOM 2026.06.01 pins compose 1.11.4,
    // the newest line that fits compileSdk 36 / AGP 8.13.2. Same-day-release mapping:
    // ui 1.11.4 and BOM 2026.06.01 are both dated 2026-07-01.) ---
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.navigation:navigation-compose:2.9.8")
    implementation("androidx.work:work-runtime-ktx:2.11.2")

    // --- Unit tests (JVM) ---
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")

    // --- Instrumented / Compose UI tests ---
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("junit:junit:4.13.2")
    // e2e counterpart drives the REAL protocol stack (libsignal/Tink surface)
    androidTestImplementation(project(":android"))
    androidTestImplementation("org.signal:libsignal-android:0.102.1")
    androidTestImplementation("com.google.crypto.tink:tink-android:1.23.0")
    androidTestImplementation("net.zetetic:sqlcipher-android:4.17.0")
    androidTestImplementation("androidx.sqlite:sqlite:2.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
