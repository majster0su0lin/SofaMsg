package com.sofamsg.app

import android.app.Application
import android.util.Log

/**
 * SofaMsg Application class.
 *
 * Responsible for one-time initialization that must happen before any
 * Activity is created:
 *   1. Configure JNA native library search paths
 *   2. Load the native Rust library (libsilentbell_ffi.so)
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
     * Load the Rust shared library and set up JNA paths.
     */
    private fun loadNativeLibrary() {
        try {
            val nativeDir = applicationInfo.nativeLibraryDir
            if (!nativeDir.isNullOrEmpty()) {
                System.setProperty("jna.library.path", nativeDir)
                System.setProperty("jna.boot.library.path", nativeDir)
            }
            System.loadLibrary("silentbell_ffi")
            nativeLibLoaded = true
            Log.i(TAG, "Native library loaded successfully from $nativeDir")
        } catch (e: Throwable) {
            nativeLibLoaded = false
            Log.e(TAG, "Failed to load native library: ${e.message}", e)
        }
    }
}
