package com.sofamsg.app

import android.app.Application
import android.util.Log

/**
 * SofaMsg Application class.
 *
 * Responsible for one-time initialization that must happen before any
 * Activity is created:
 *   1. Load the native Rust library (libsilentbell_ffi.so)
 *   2. Any future global singletons (database, P2P node, etc.)
 *
 * Declared in AndroidManifest.xml as `android:name=".SofaMsgApp"`.
 */
class SofaMsgApp : Application() {

    companion object {
        private const val TAG = "SofaMsgApp"

        /**
         * Whether the native library loaded successfully.
         * UI code checks this before calling any FFI functions.
         */
        var nativeLibLoaded: Boolean = false
            private set
    }

    override fun onCreate() {
        super.onCreate()
        loadNativeLibrary()
    }

    /**
     * Load the Rust shared library.
     *
     * The .so file is placed in jniLibs/<abi>/ by the CI pipeline
     * and packaged into the APK automatically by the Android build system.
     * System.loadLibrary strips the "lib" prefix and ".so" suffix.
     */
    private fun loadNativeLibrary() {
        try {
            System.loadLibrary("silentbell_ffi")
            nativeLibLoaded = true
            Log.i(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            nativeLibLoaded = false
            Log.e(TAG, "Failed to load native library: ${e.message}")
        }
    }
}
