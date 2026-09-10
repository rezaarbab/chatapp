plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "chatapp.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // libsignal-android 0.102.1 AAR metadata requires core library desugaring
        coreLibraryDesugaringEnabled = true
    }

    packaging {
        resources {
            // Desktop natives pulled transitively from libsignal-client must not ship on Android
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
    // Official Signal Android artifact (contains Android .so natives)
    implementation("org.signal:libsignal-android:0.102.1")
    // SQLCipher Community edition. 4.17.0 is the newest release whose AAR metadata
    // (minCompileSdk=1) is compatible with compileSdk 35; 4.18+ requires compileSdk 37.
    implementation("net.zetetic:sqlcipher-android:4.17.0")
    // Required: sqlcipher-android's SQLiteDatabase exposes androidx.sqlite.db supertypes
    implementation("androidx.sqlite:sqlite:2.7.0")

    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
