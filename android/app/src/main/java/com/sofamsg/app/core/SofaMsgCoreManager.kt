package com.sofamsg.app.core

import android.content.Context
import android.util.Log
import uniffi.sofamsg.*
import java.io.File

/**
 * SofaMsg Core Manager.
 *
 * High-level Kotlin wrapper over the UniFFI Rust bindings (uniffi.sofamsg).
 * Handles:
 *   • Identity management & keypair persistence
 *   • PIN derivation & vault opening (real vault vs duress decoy vault)
 *   • Encrypted storage CRUD operations
 *   • Decoy conversation loading
 *   • QR and URI invitation creation/parsing
 *   • Queue ID derivation for P2P networking
 */
class SofaMsgCoreManager(private val context: Context) {

    companion object {
        private const val TAG = "SofaMsgCoreManager"
        private const val DB_NAME = "sofamsg_vault.db"
        private const val PREFS_NAME = "sofamsg_prefs"
        private const val KEY_SALT = "vault_salt"
        private const val KEY_PIN_SET = "is_pin_set"
        private const val KEY_IDENTITY_KEY = "identity_private_key_hex"

        @Volatile
        private var activeDb: FfiDatabase? = null
        @Volatile
        private var activeVaultKey: FfiVaultKey? = null
        @Volatile
        var isDuressMode: Boolean = false
            private set
    }

    /**
     * Check if a PIN has been created and the vault database initialized.
     */
    fun isPinSet(): Boolean {
        return try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val hasFlag = prefs.getBoolean(KEY_PIN_SET, false)
            val dbExists = File(context.filesDir, DB_NAME).exists()
            hasFlag && dbExists
        } catch (e: Throwable) {
            false
        }
    }

    /**
     * Set up a new PIN on first launch.
     *
     * Removes any stale vault database files and generates a fresh salt
     * before deriving the new key and creating the database schema.
     */
    fun setupPin(pin: String): Boolean {
        return try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

            // Delete any existing/stale vault database files to start fresh
            val dbFile = File(context.filesDir, DB_NAME)
            val decoyDbFile = File(context.filesDir, "decoy_$DB_NAME")
            if (dbFile.exists()) dbFile.delete()
            if (decoyDbFile.exists()) decoyDbFile.delete()
            File(context.filesDir, "$DB_NAME-journal").delete()
            File(context.filesDir, "$DB_NAME-wal").delete()

            // Generate a fresh 16-byte salt for the new PIN
            val newSalt = ByteArray(16)
            java.security.SecureRandom().nextBytes(newSalt)
            val newSaltHex = bytesToHex(newSalt)
            prefs.edit().putString(KEY_SALT, newSaltHex).apply()

            // Derive key and initialize new vault database
            val vaultKey = FfiVaultKey.derive(pin, newSalt)
            dbFile.parentFile?.mkdirs()
            val db = FfiDatabase.open(dbFile.absolutePath, vaultKey)
            db.ensureSchema()

            // Update active state and mark PIN as set
            activeVaultKey = vaultKey
            activeDb = db
            isDuressMode = false
            prefs.edit().putBoolean(KEY_PIN_SET, true).apply()

            Log.i(TAG, "Successfully initialized fresh vault database for new PIN")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to setup new PIN vault: ${e.message}", e)
            false
        }
    }

    /**
     * Get or create a 16-byte random salt for Argon2id PIN derivation.
     */
    fun getOrCreateSalt(): ByteArray {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saltHex = prefs.getString(KEY_SALT, null)
        if (saltHex != null) {
            return hexToBytes(saltHex)
        }
        val newSalt = ByteArray(16)
        java.security.SecureRandom().nextBytes(newSalt)
        val newSaltHex = bytesToHex(newSalt)
        prefs.edit().putString(KEY_SALT, newSaltHex).apply()
        return newSalt
    }

    /**
     * Get or create the local user's identity keypair.
     */
    fun getOrCreateIdentity(): IdentityResult {
        return createNewIdentity()
    }

    /**
     * Unlock the application with the user's PIN.
     *
     * Derives the vault key using Argon2id, opens the SQLCipher database,
     * and sets up the schema.
     *
     * @param pin The 4–8 digit user PIN
     * @param isDuress If true, unlocks in duress decoy mode
     */
    fun unlock(pin: String, isDuress: Boolean = false): Boolean {
        return try {
            val salt = getOrCreateSalt()
            val vaultKey = FfiVaultKey.derive(pin, salt)
            activeVaultKey = vaultKey
            isDuressMode = isDuress

            val dbFile = File(context.filesDir, if (isDuress) "decoy_$DB_NAME" else DB_NAME)
            dbFile.parentFile?.mkdirs()
            val db = FfiDatabase.open(dbFile.absolutePath, vaultKey)
            db.ensureSchema()
            activeDb = db

            if (!isDuress) {
                val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                prefs.edit().putBoolean(KEY_PIN_SET, true).apply()
            }

            if (isDuress) {
                // Seed decoy conversations into decoy database if empty
                val decoySeed = ByteArray(32) { (it + 1).toByte() }
                val decoys = generateDecoyConversations(decoySeed)
                if (db.getRecentConversations(1u).isEmpty()) {
                    val now = System.currentTimeMillis() / 1000
                    for (convo in decoys) {
                        for (msg in convo.messages) {
                            db.insertMessage(
                                peerAccountId = convo.peerAccountId,
                                body = msg.body,
                                sentAt = now - msg.secondsAgo.toLong(),
                                isOutgoing = msg.isOutgoing
                            )
                        }
                    }
                }
            }

            Log.i(TAG, "Successfully unlocked vault (isDuress=$isDuress)")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to unlock vault: ${e.message}", e)
            false
        }
    }

    /**
     * Get recent conversations from the unlocked database.
     */
    fun getRecentConversations(limit: Int = 50): List<FfiStoredMessage> {
        val db = activeDb ?: return emptyList()
        return try {
            db.getRecentConversations(limit.toUInt())
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to fetch conversations: ${e.message}")
            emptyList()
        }
    }

    /**
     * Get all messages for a specific peer.
     */
    fun getMessages(peerAccountId: String): List<FfiStoredMessage> {
        val db = activeDb ?: return emptyList()
        return try {
            db.getMessages(peerAccountId)
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to fetch messages: ${e.message}")
            emptyList()
        }
    }

    /**
     * Save an outgoing or incoming message to the local encrypted vault.
     */
    fun saveMessage(peerAccountId: String, body: String, isOutgoing: Boolean): Long {
        val db = activeDb ?: return -1
        return try {
            val now = System.currentTimeMillis() / 1000
            db.insertMessage(peerAccountId, body, now, isOutgoing)
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to save message: ${e.message}")
            -1
        }
    }

    /**
     * Generate an invitation URI (sofamsg://connect?...) for sharing.
     */
    fun createInvitation(displayName: String? = null): String? {
        return try {
            val identity = getOrCreateIdentity()
            val pubKeyBytes = hexToBytes(identity.publicKeyHex)
            val queueIdStr = deriveQueueId(pubKeyBytes)
            val queueIdBytes = bs58Decode(queueIdStr)

            val payload = createInvite(pubKeyBytes, queueIdBytes, displayName)
            inviteToUri(payload)
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to create invitation: ${e.message}")
            null
        }
    }

    /**
     * Parse and validate an incoming invitation URI.
     */
    fun parseInvitation(uri: String): FfiInvitePayload? {
        return try {
            val payload = inviteFromUri(uri)
            if (inviteValidate(payload)) {
                payload
            } else {
                Log.w(TAG, "Invitation validation failed (account ID mismatch)")
                null
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to parse invitation: ${e.message}")
            null
        }
    }

    // ── Helper utilities ──

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
        }
        return data
    }

    private fun bs58Decode(input: String): ByteArray {
        val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bi = java.math.BigInteger.ZERO
        for (c in input) {
            val alphaIndex = ALPHABET.indexOf(c)
            require(alphaIndex != -1) { "Invalid Base58 character: $c" }
            bi = bi.multiply(java.math.BigInteger.valueOf(58)).add(java.math.BigInteger.valueOf(alphaIndex.toLong()))
        }
        var bytes = bi.toByteArray()
        if (bytes.isNotEmpty() && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        var leadingZeros = 0
        while (leadingZeros < input.length && input[leadingZeros] == '1') {
            leadingZeros++
        }
        val result = ByteArray(leadingZeros + bytes.size)
        System.arraycopy(bytes, 0, result, leadingZeros, bytes.size)
        return result
    }
}
