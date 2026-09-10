pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        // Official Signal libsignal artifacts (Maven Central is stale for libsignal)
        maven("https://build-artifacts.signal.org/libraries/maven/")
        mavenCentral()
    }
}

rootProject.name = "chatapp"
include(":prototype")
