/// Decoy content generation for the duress vault.
///
/// When a user unlocks with their duress PIN, the app must display a
/// convincing, innocuous set of conversations — not an empty vault
/// (which would scream "this is the decoy"). This module generates
/// deterministic fake conversations seeded from the duress vault key
/// so the same duress PIN always produces the same decoy content.
///
/// # Design principles
///
/// 1. **Deterministic from seed** — given the same 32-byte seed (the
///    duress vault key), always produce identical decoy content. This
///    prevents the decoy vault from "changing" between unlocks, which
///    would be suspicious.
///
/// 2. **Plausible volume** — generate 3–5 conversations with 4–10
///    messages each. Too few looks unused; too many looks fabricated.
///
/// 3. **Mundane content** — everyday topics: weather, lunch plans,
///    weekend activities, work meetings. Nothing crypto-related or
///    security-related that might look like it belongs in a "hidden"
///    vault.
///
/// 4. **Realistic timestamps** — messages spread over the last 1–7
///    days with natural gaps (not perfectly evenly spaced).

use sha2::{Sha256, Digest};

/// A single decoy message.
#[derive(Debug, Clone)]
pub struct DecoyMessage {
    pub body: String,
    pub is_outgoing: bool,
    /// Seconds before "now" (the unlock time) that this message was "sent."
    /// The caller subtracts this from the current timestamp to produce a
    /// realistic `sent_at` value.
    pub seconds_ago: u64,
}

/// A decoy conversation (one peer with several messages).
#[derive(Debug, Clone)]
pub struct DecoyConversation {
    /// The fake peer's Account ID (starts with `sb_`).
    pub peer_account_id: String,
    /// The fake peer's display name.
    pub peer_name: String,
    /// Messages in chronological order (largest `seconds_ago` first).
    pub messages: Vec<DecoyMessage>,
}

/// A simple deterministic PRNG seeded from a byte slice.
/// Uses a 64-bit xorshift* variant — fast, deterministic, NOT
/// cryptographically secure (doesn't need to be; this is content
/// generation, not key material).
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn from_seed(seed: &[u8]) -> Self {
        // Mix the seed bytes into a single u64 via SHA-256, then take
        // the first 8 bytes. This gives good distribution even if the
        // seed has low entropy in some bytes.
        let hash = Sha256::digest(seed);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&hash[..8]);
        let mut state = u64::from_le_bytes(buf);
        if state == 0 { state = 1; } // xorshift needs non-zero state
        SeededRng { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Random u64 in [0, bound)
    fn next_bounded(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    /// Pick a random element from a slice.
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = self.next_bounded(items.len() as u64) as usize;
        &items[idx]
    }
}

// ── Corpus of mundane conversation snippets ─────────────────

const PEER_FIRST_NAMES: &[&str] = &[
    "Jamie", "Alex", "Sam", "Jordan", "Taylor",
    "Morgan", "Casey", "Riley", "Avery", "Quinn",
    "Drew", "Sage", "Blake", "Hayden", "Rowan",
];

/// Conversation "scripts" — each is a sequence of (is_outgoing, text)
/// pairs forming a plausible exchange. The generator picks from these
/// and shuffles timing.
const SCRIPTS: &[&[(&str, bool)]] = &[
    // Script 0: lunch plans
    &[
        ("Hey, want to grab lunch today?", false),
        ("Sure! What time works for you?", true),
        ("How about 12:30? That new ramen place?", false),
        ("Sounds good, meet you there", true),
        ("Running 5 min late, order me the miso one please", false),
        ("Got it 👍", true),
    ],
    // Script 1: weekend plans
    &[
        ("What are you up to this weekend?", false),
        ("Probably going to the farmers market Saturday morning", true),
        ("Oh nice, I heard they have fresh strawberries now", false),
        ("Yeah! Want to come?", true),
        ("I'm in. What time?", false),
        ("Like 9am? Before it gets crowded", true),
        ("Perfect, see you then", false),
    ],
    // Script 2: work meeting
    &[
        ("Did you get the meeting invite for 3pm?", false),
        ("Just saw it, yeah. Any idea what it's about?", true),
        ("I think it's the quarterly review", false),
        ("Ah ok, I'll prep those numbers real quick", true),
        ("Good call. See you in the meeting", false),
    ],
    // Script 3: weather chat
    &[
        ("Is it raining where you are?", true),
        ("Pouring. I forgot my umbrella 🌧️", false),
        ("Same here, this weather is awful", true),
        ("It's supposed to clear up by Thursday apparently", false),
        ("Finally, I'm so tired of the rain", true),
    ],
    // Script 4: movie recommendation
    &[
        ("Have you seen that new movie everyone's talking about?", false),
        ("Which one?", true),
        ("The one with the time travel subplot", false),
        ("Not yet, is it good?", true),
        ("Really good actually, I'd give it an 8/10", false),
        ("Ok I'll check it out tonight", true),
        ("Let me know what you think!", false),
        ("Will do 👍", true),
    ],
    // Script 5: grocery errand
    &[
        ("Can you pick up milk on the way home?", false),
        ("Sure, anything else?", true),
        ("Bread and eggs if they have them", false),
        ("Got it. Do you want the sourdough or the regular?", true),
        ("Sourdough please!", false),
        ("Done, heading home now", true),
    ],
    // Script 6: fitness
    &[
        ("Want to go for a run tomorrow morning?", true),
        ("What time were you thinking?", false),
        ("6:30am? Before it gets hot", true),
        ("Ugh that's early but ok", false),
        ("We can do 7 if you want", true),
        ("7 is better. Meet at the park?", false),
        ("Perfect, see you then", true),
    ],
    // Script 7: gift idea
    &[
        ("Any ideas for Mom's birthday gift?", false),
        ("She mentioned wanting a new cookbook", true),
        ("Oh that's a good idea, the Italian one?", false),
        ("Yeah, I can order it online. We can split it?", true),
        ("Sounds good, just send me the link", false),
    ],
];

/// Generate a deterministic fake account ID from seed bytes.
fn generate_fake_account_id(rng: &mut SeededRng) -> String {
    let chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut id = String::from("sb_");
    for _ in 0..44 {
        let idx = rng.next_bounded(chars.len() as u64) as usize;
        id.push(chars[idx] as char);
    }
    id
}

/// Generate decoy conversations from a 32-byte seed (typically the
/// raw bytes of the duress vault key).
///
/// Returns 3–5 conversations with realistic content and timing.
pub fn generate_decoy_content(seed: &[u8; 32]) -> Vec<DecoyConversation> {
    let mut rng = SeededRng::from_seed(seed);

    // Pick how many conversations: 3–5
    let num_convos = 3 + rng.next_bounded(3) as usize; // 3, 4, or 5

    let mut conversations = Vec::with_capacity(num_convos);

    // Track which scripts we've used so we don't repeat
    let mut used_scripts: Vec<usize> = Vec::new();

    for _ in 0..num_convos {
        // Pick a script we haven't used yet
        let script_idx = loop {
            let idx = rng.next_bounded(SCRIPTS.len() as u64) as usize;
            if !used_scripts.contains(&idx) {
                break idx;
            }
            // If we've used all scripts, allow repeats
            if used_scripts.len() >= SCRIPTS.len() {
                break idx;
            }
        };
        used_scripts.push(script_idx);
        let script = SCRIPTS[script_idx];

        // Generate peer identity
        let peer_name = rng.pick(PEER_FIRST_NAMES).to_string();
        let peer_account_id = generate_fake_account_id(&mut rng);

        // Generate message timestamps
        // Base: 1–7 days ago for the first message
        let base_seconds_ago = (1 + rng.next_bounded(6)) * 86400 // 1–7 days
            + rng.next_bounded(43200); // +0–12 hours of jitter

        let mut messages = Vec::with_capacity(script.len());

        for (i, &(text, is_outgoing)) in script.iter().enumerate() {
            // Each subsequent message is 1–30 minutes after the previous
            let gap = if i == 0 {
                0
            } else {
                60 + rng.next_bounded(1740) // 1–30 minutes
            };

            let seconds_ago = if i == 0 {
                base_seconds_ago
            } else {
                // Previous message's seconds_ago minus the gap
                // (so timestamps go forward in time)
                let prev = messages.last().map(|m: &DecoyMessage| m.seconds_ago).unwrap_or(base_seconds_ago);
                prev.saturating_sub(gap)
            };

            messages.push(DecoyMessage {
                body: text.to_string(),
                is_outgoing,
                seconds_ago,
            });
        }

        conversations.push(DecoyConversation {
            peer_account_id,
            peer_name,
            messages,
        });
    }

    conversations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_same_seed() {
        let seed = [42u8; 32];
        let a = generate_decoy_content(&seed);
        let b = generate_decoy_content(&seed);

        assert_eq!(a.len(), b.len());
        for (ca, cb) in a.iter().zip(b.iter()) {
            assert_eq!(ca.peer_account_id, cb.peer_account_id);
            assert_eq!(ca.peer_name, cb.peer_name);
            assert_eq!(ca.messages.len(), cb.messages.len());
            for (ma, mb) in ca.messages.iter().zip(cb.messages.iter()) {
                assert_eq!(ma.body, mb.body);
                assert_eq!(ma.is_outgoing, mb.is_outgoing);
                assert_eq!(ma.seconds_ago, mb.seconds_ago);
            }
        }
    }

    #[test]
    fn different_seeds_produce_different_content() {
        let a = generate_decoy_content(&[1u8; 32]);
        let b = generate_decoy_content(&[2u8; 32]);

        // At minimum, peer IDs should differ
        assert_ne!(
            a[0].peer_account_id,
            b[0].peer_account_id,
        );
    }

    #[test]
    fn generates_three_to_five_conversations() {
        // Test several seeds to check range
        for seed_byte in 0u8..20 {
            let content = generate_decoy_content(&[seed_byte; 32]);
            assert!(content.len() >= 3 && content.len() <= 5,
                "Expected 3-5 conversations, got {}", content.len());
        }
    }

    #[test]
    fn all_peer_ids_start_with_prefix() {
        let content = generate_decoy_content(&[99u8; 32]);
        for convo in &content {
            assert!(convo.peer_account_id.starts_with("sb_"),
                "Peer ID should start with sb_, got: {}", convo.peer_account_id);
        }
    }

    #[test]
    fn messages_have_decreasing_seconds_ago() {
        let content = generate_decoy_content(&[77u8; 32]);
        for convo in &content {
            for window in convo.messages.windows(2) {
                assert!(window[0].seconds_ago >= window[1].seconds_ago,
                    "Messages should be in chronological order (decreasing seconds_ago)");
            }
        }
    }

    #[test]
    fn messages_have_plausible_content() {
        let content = generate_decoy_content(&[55u8; 32]);
        for convo in &content {
            assert!(!convo.messages.is_empty(), "Conversations should have messages");
            assert!(convo.messages.len() >= 4, "Should have at least 4 messages");
            for msg in &convo.messages {
                assert!(!msg.body.is_empty(), "Messages should not be empty");
            }
        }
    }
}
