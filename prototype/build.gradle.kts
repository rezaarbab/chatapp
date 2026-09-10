plugins {
    kotlin("jvm")
}

kotlin {
    // libsignal-client 0.102.1 is compiled with Java 21 bytecode
    jvmToolchain(21)
}

dependencies {
    // Official Signal library. Same Java API as libsignal-android; ships desktop
    // native libraries (Windows/Linux/macOS) so the protocol layer is testable on JVM.
    implementation("org.signal:libsignal-client:0.102.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = false
    }
}
