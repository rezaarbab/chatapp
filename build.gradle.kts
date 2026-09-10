plugins {
    // libsignal-client 0.102.1 ships Kotlin 2.2 metadata; compiler must be >= 2.2
    kotlin("jvm") version "2.2.20" apply false
    kotlin("android") version "2.2.20" apply false
    id("com.android.library") version "8.7.3" apply false
}
