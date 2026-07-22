use rand_core::{OsRng, RngCore};
use rusqlite::Connection;

/// A message as stored in the local encrypted database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub id: i64,
    pub peer_account_id: String,
    pub body: String,
    pub sent_at: i64,
    pub is_outgoing: bool,
}

pub fn open_encrypted_db(path: &str, key: &crate::vault::VaultKey) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;

    let key_hex = key.as_hex();
    conn.pragma_update(None, "key", format!("x'{key_hex}'"))?;

    Ok(conn)
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_account_id TEXT NOT NULL,
            body TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            is_outgoing INTEGER NOT NULL
        )",
        (),
    )?;
    // Chaff blocks table — random-sized blobs that pad the encrypted DB
    // file to hide the true number of real messages.
    //
    // Why this matters: if the real vault has 200 messages and the duress
    // vault has 10, the file size difference is obvious. An examiner could
    // compare sizes and deduce "the larger one is the real vault."
    //
    // Chaff blocks make both vaults roughly the same size regardless of
    // how many real messages each contains.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chaff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data BLOB NOT NULL
        )",
        (),
    )?;
    Ok(())
}

/// Target database size in bytes. Both the real vault and the duress vault
/// are padded to at least this size, so file size doesn't reveal which
/// vault has more real content.
///
/// 512 KiB is large enough to hold many thousands of messages' worth of
/// chaff, small enough to not waste meaningful storage on a phone.
const TARGET_DB_SIZE_BYTES: u64 = 512 * 1024;

/// Size of each individual chaff block in bytes.
/// Using a fixed size prevents the chaff blocks themselves from leaking
/// information via their size distribution.
const CHAFF_BLOCK_SIZE: usize = 4096;

/// Insert chaff blocks to pad the database file to at least `TARGET_DB_SIZE_BYTES`.
///
/// Call this after writing real messages or after initial vault creation
/// to ensure the file size is consistent. Idempotent — if the DB is
/// already large enough, no blocks are added.
///
/// The chaff data is random bytes (from the OS CSPRNG), so it's
/// indistinguishable from encrypted content to anyone without the key.
pub fn pad_chaff(conn: &Connection, db_path: &str) -> rusqlite::Result<u32> {
    let current_size = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);

    if current_size >= TARGET_DB_SIZE_BYTES {
        return Ok(0);
    }

    let needed_bytes = TARGET_DB_SIZE_BYTES - current_size;
    // Each chaff block adds CHAFF_BLOCK_SIZE bytes of payload, plus some
    // SQLite overhead (~50 bytes per row). We slightly over-pad rather
    // than under-pad.
    let blocks_needed = (needed_bytes as usize / CHAFF_BLOCK_SIZE).max(1);

    let mut inserted = 0u32;
    for _ in 0..blocks_needed {
        let mut block = vec![0u8; CHAFF_BLOCK_SIZE];
        OsRng.fill_bytes(&mut block);
        conn.execute("INSERT INTO chaff (data) VALUES (?1)", [&block[..]])?;
        inserted += 1;
    }

    Ok(inserted)
}

/// Get the current number of chaff blocks in the database.
pub fn chaff_count(conn: &Connection) -> rusqlite::Result<u32> {
    conn.query_row("SELECT COUNT(*) FROM chaff", (), |row| row.get(0))
}

/// Remove all chaff blocks. Useful before re-padding after bulk operations.
pub fn clear_chaff(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM chaff", ())?;
    Ok(())
}

/// Insert a message into the local encrypted database.
///
/// Returns the row ID of the newly inserted message.
pub fn insert_message(
    conn: &Connection,
    peer_account_id: &str,
    body: &str,
    sent_at: i64,
    is_outgoing: bool,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO messages (peer_account_id, body, sent_at, is_outgoing) VALUES (?1, ?2, ?3, ?4)",
        (peer_account_id, body, sent_at, is_outgoing as i32),
    )?;
    Ok(conn.last_insert_rowid())
}

/// Retrieve all messages for a given peer, ordered by sent_at ascending.
pub fn get_messages(
    conn: &Connection,
    peer_account_id: &str,
) -> rusqlite::Result<Vec<StoredMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, peer_account_id, body, sent_at, is_outgoing
         FROM messages
         WHERE peer_account_id = ?1
         ORDER BY sent_at ASC",
    )?;

    let rows = stmt.query_map([peer_account_id], |row| {
        Ok(StoredMessage {
            id: row.get(0)?,
            peer_account_id: row.get(1)?,
            body: row.get(2)?,
            sent_at: row.get(3)?,
            is_outgoing: row.get::<_, i32>(4)? != 0,
        })
    })?;

    rows.collect()
}

/// Retrieve the most recent conversations (distinct peers) with their
/// latest message, ordered by most recent first.
///
/// Returns up to `limit` conversations.
pub fn get_recent_conversations(
    conn: &Connection,
    limit: u32,
) -> rusqlite::Result<Vec<StoredMessage>> {
    let mut stmt = conn.prepare(
        "SELECT m.id, m.peer_account_id, m.body, m.sent_at, m.is_outgoing
         FROM messages m
         INNER JOIN (
             SELECT peer_account_id, MAX(sent_at) AS max_sent
             FROM messages
             GROUP BY peer_account_id
         ) latest ON m.peer_account_id = latest.peer_account_id
                  AND m.sent_at = latest.max_sent
         ORDER BY m.sent_at DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit], |row| {
        Ok(StoredMessage {
            id: row.get(0)?,
            peer_account_id: row.get(1)?,
            body: row.get(2)?,
            sent_at: row.get(3)?,
            is_outgoing: row.get::<_, i32>(4)? != 0,
        })
    })?;

    rows.collect()
}

/// Delete a specific message by ID.
pub fn delete_message(conn: &Connection, message_id: i64) -> rusqlite::Result<bool> {
    let affected = conn.execute("DELETE FROM messages WHERE id = ?1", [message_id])?;
    Ok(affected > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::derive_key;

    fn test_db_path(name: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(name);
        path.to_string_lossy().into_owned()
    }

    fn setup_test_db(name: &str) -> (Connection, String) {
        let salt = [1u8; 16];
        let key = derive_key("1234", &salt);
        let path = test_db_path(name);
        let _ = std::fs::remove_file(&path);
        let conn = open_encrypted_db(&path, &key).unwrap();
        ensure_schema(&conn).unwrap();
        (conn, path)
    }

    #[test]
    fn correct_key_can_read_back_written_data() {
        let (conn, path) = setup_test_db("sofamsg_test_correct.db");

        let id = insert_message(&conn, "sb_test_peer", "hello sofa", 1700000000, true).unwrap();
        assert_eq!(id, 1);

        let msgs = get_messages(&conn, "sb_test_peer").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "hello sofa");
        assert!(msgs[0].is_outgoing);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_key_does_not_crash_but_cannot_read_real_data() {
        let real_salt = [1u8; 16];
        let wrong_salt = [2u8; 16];
        let real_key = derive_key("1234", &real_salt);
        let wrong_key = derive_key("9999", &wrong_salt);

        let path = test_db_path("sofamsg_test_wrongkey.db");
        let _ = std::fs::remove_file(&path);

        {
            let conn = open_encrypted_db(&path, &real_key).unwrap();
            ensure_schema(&conn).unwrap();
            insert_message(&conn, "sb_test_peer", "real secret", 1700000000, true).unwrap();
        }

        let conn2 = open_encrypted_db(&path, &wrong_key).unwrap();
        let result = conn2.query_row("SELECT body FROM messages WHERE id = 1", (), |row| {
            row.get::<_, String>(0)
        });
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn insert_and_retrieve_multiple_messages() {
        let (conn, path) = setup_test_db("sofamsg_test_multi.db");

        insert_message(&conn, "sb_alice", "hello", 1000, true).unwrap();
        insert_message(&conn, "sb_alice", "how are you?", 1001, true).unwrap();
        insert_message(&conn, "sb_alice", "i'm good!", 1002, false).unwrap();
        insert_message(&conn, "sb_bob", "hey", 1003, false).unwrap();

        let alice_msgs = get_messages(&conn, "sb_alice").unwrap();
        assert_eq!(alice_msgs.len(), 3);
        assert_eq!(alice_msgs[0].body, "hello");
        assert!(alice_msgs[0].is_outgoing);
        assert_eq!(alice_msgs[2].body, "i'm good!");
        assert!(!alice_msgs[2].is_outgoing);

        let bob_msgs = get_messages(&conn, "sb_bob").unwrap();
        assert_eq!(bob_msgs.len(), 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn get_recent_conversations_returns_latest_per_peer() {
        let (conn, path) = setup_test_db("sofamsg_test_recent.db");

        insert_message(&conn, "sb_alice", "old msg", 1000, true).unwrap();
        insert_message(&conn, "sb_alice", "new msg", 2000, false).unwrap();
        insert_message(&conn, "sb_bob", "bob msg", 1500, true).unwrap();
        insert_message(&conn, "sb_carol", "carol msg", 500, false).unwrap();

        let recent = get_recent_conversations(&conn, 10).unwrap();
        assert_eq!(recent.len(), 3);
        // Most recent first: alice (2000), bob (1500), carol (500)
        assert_eq!(recent[0].peer_account_id, "sb_alice");
        assert_eq!(recent[0].body, "new msg");
        assert_eq!(recent[1].peer_account_id, "sb_bob");
        assert_eq!(recent[2].peer_account_id, "sb_carol");

        // Test limit
        let recent2 = get_recent_conversations(&conn, 2).unwrap();
        assert_eq!(recent2.len(), 2);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn delete_message_removes_specific_message() {
        let (conn, path) = setup_test_db("sofamsg_test_delete.db");

        let _id1 = insert_message(&conn, "sb_alice", "keep", 1000, true).unwrap();
        let id2 = insert_message(&conn, "sb_alice", "delete me", 1001, true).unwrap();

        assert!(delete_message(&conn, id2).unwrap());

        let msgs = get_messages(&conn, "sb_alice").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "keep");

        // Deleting non-existent returns false
        assert!(!delete_message(&conn, 999).unwrap());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_peer_returns_empty_vec() {
        let (conn, path) = setup_test_db("sofamsg_test_empty.db");

        let msgs = get_messages(&conn, "sb_nobody").unwrap();
        assert!(msgs.is_empty());

        std::fs::remove_file(&path).ok();
    }
}
