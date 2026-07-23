// SofaMsg — Android project root settings
// Declares the app module for the Gradle build.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "SofaMsg"
include(":app")
