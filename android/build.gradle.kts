// SofaMsg — Root build file
//
// This applies the Android and Kotlin plugins at the project level
// so they are available to the :app subproject.

plugins {
    id("com.android.application") version "8.2.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.22" apply false
}
