# sofamsg — Project Context for AI Assistants

Read this whole file before making changes. It exists so any AI (or
human) picking up this project mid-stream understands the design
intent, the current implementation state, and — critically — which
parts are load-bearing security decisions that should NOT be
"simplified" or "cleaned up" without understanding why they're written
the way they are.

## What sofamsg is

A peer-to-peer, serverless messaging app with three core properties:
1. **No central server** — no company can be subpoenaed, hacked, or
   shut down to take the network offline, because there is no
   "network operator," just peers.
2. **No registration / zero-link identity** — accounts are just
   Ed25519 keypairs generated locally. There is no email, phone
   number, or username tied to a real identity anywhere.
3. **Plausible deniability at rest** — the local message vault is
   protected by a PIN, but a second "duress" PIN opens a different,
   decoy vault instead of erroring or refusing. Wrong PINs produce
   silent garbage instead of an "incorrect password" message.

Full original architecture writeup: see the two source design docs the
project owner (plswrk) pasted at project start — "Project SilentBell"
v1 (blind-signature email-linked identity) and v2 (pure local-keypair
identity, which is the version actually being built — the email-based
onboarding in v1 was explicitly discarded in favor of v2's local
keygen). If those docs aren't in this repo yet, ask the project owner
to paste them into `docs/ORIGINAL_DESIGN.md`.

**Implication for AI assistants:** explain cryptographic and systems
decisions thoroughly, don't assume prior familiarity with Rust
idioms or crypto library APIs, but DO assume strong intuition for
low-level/systems concepts (memory, registers, bit manipulation) — that
part doesn't need over-explaining.

## Repository layout

```
silentbell/
├── core/                          # Rust crypto + protocol core (this is what exists so far)
│   ├── Cargo.toml
│   ├── docs/
│   │   └── VAULT_THREAT_MODEL.md  # READ BEFORE touching vault.rs
│   └── src/
│       ├── lib.rs                 # module wiring + public API surface
│       ├── keys.rs                # Ed25519 keypair generation
│       ├── identity.rs            # public key -> shareable Account ID
│       └── vault.rs                # PIN -> AES key derivation, silent-fail decrypt
├── app/                            # NOT YET STARTED - Kotlin/Flutter mobile client
├── p2p/                            # NOT YET STARTED - libp2p networking layer
├── README.md                       # this file
└── .github/workflows/              # NOT YET STARTED - CI for cross-compiled APK builds
```

## Current implementation state (as of this writing)

**Done and tested:**
- `keys.rs` — `Keypair::generate()` using OS entropy (`OsRng`), Ed25519
  via `ed25519-dalek`. 2 tests passing.
- `identity.rs` — `derive_account_id()`, SHA-256 of the public key,
  base58-encoded with an `sb_` prefix. 3 tests passing.
- `vault.rs` — `derive_key()` (Argon2id, PIN + salt -> 256-bit key),
  `encrypt()`/`decrypt()` (AES-256-CBC, no auth tag, by design). 4
  tests passing (pending a wiring bug — see below).

**In progress / has a known bug:** `vault.rs` was just added but a
`mod vault;` declaration ended up misplaced during manual file editing
in Termux (nano), so the crate currently fails to compile. This is a
file-organization bug, not a design bug — the module content itself is
believed correct, just not correctly wired into `lib.rs`.

**Not started yet:**
- Actual SQLCipher-backed database file (vault.rs currently
  encrypts/decrypts raw byte blobs in memory; it doesn't touch a real
  DB file or the "chaff blocks to hide true database size" idea from
  the original design doc)
- Realistic decoy content generation for the duress vault
- The P2P/DHT layer (Queue IDs, doorbell wake-up ping, push-to-pull
  message flow)
- Blind-signature or any identity verification (deliberately dropped —
  see "Design decisions" below)
- Out-of-band connection methods (QR code, invitation links)
- Android FFI boundary (Kotlin <-> Rust via JNI/UniFFI, not yet chosen)
- Any UI at all

## Design decisions already made (don't relitigate without cause)

- **No email verification / no blind signatures.** The original v1
  design used blind RSA signatures for optional email verification.
  This was explicitly dropped in favor of pure local keypair identity
  (v2). If blind signatures come up again, that's a deliberate
  reversal, not an oversight — confirm with the project owner first.
- **AES-256-CBC without an authentication tag is intentional**, not a
  missed best-practice. Full reasoning in
  `core/docs/VAULT_THREAT_MODEL.md`. Do not "fix" this by switching to
  GCM without reading that doc — it would break the silent-fail
  deniability property.
- **Argon2id, not PBKDF2 or bcrypt**, for PIN-to-key derivation —
  current OWASP-recommended choice.
- **Separate random salts for the real vault and the duress vault** —
  reusing one salt for both would make the two vaults
  cryptographically linkable, undermining deniability.
- **Ed25519 over RSA** for identity keys — smaller keys/signatures,
  better fit for a P2P system passing keys around in QR codes and
  URLs.
- **Monorepo, not split repos** — chosen because the Rust core, FFI
  boundary, and mobile client will change together frequently while
  this is a solo project; splitting repos would add coordination
  overhead with no current benefit.

## How to work with the project owner

- They like each step explained: what was done and why, not just the
  end code.
- They want to genuinely understand the security properties of what's
  being built, not just be told "it's secure" — engage with specifics
  (which primitive, which failure mode it prevents, what it doesn't
  cover) rather than reassurance.
- They compile and test primarily in Termux on-device (Poco F7 Ultra),
  not in a full IDE — so instructions should be copy-pasteable shell
  commands and nano-editable file contents, not "open your IDE and
  click X."
- Development is iterative and exploratory — expect the architecture
  to keep evolving as pieces get built and tested, not to be fully
  fixed upfront.

## Protocol details: how the doorbell mechanism should work

This is not implemented yet (see "Not started yet" above), but the
design intent is specific enough to write down now so whoever builds
it doesn't have to re-derive it from the original design docs.

**The problem it solves:** a P2P messaging app on a phone can't just
keep a socket open 24/7 waiting for messages — that drains battery
fast and gets killed by Android's background process limits anyway.
But you also can't have the sender push data directly to a sleeping
device. The doorbell is the fix: a tiny "someone wants to talk to you"
signal that's cheap enough to deliver even to a sleeping device,
separate from the actual (larger, heavier) message payload.

**Step by step:**
1. **At rest:** Both devices are asleep. Neither holds an open
   connection to the other or to any central server.
2. **User A sends a message:** Their device does NOT try to transmit
   the message directly. Instead it sends a minimal "doorbell" ping —
   just enough data to identify *which* device to wake (User B's
   device ID), nothing about content, sender, or message size. This
   ping travels via CoAP or UnifiedPush — both are designed for exactly
   this "wake a sleeping device cheaply" use case, which is why they
   were chosen over a raw persistent socket.
3. **User B's OS wakes the app:** The doorbell ping triggers the OS's
   push-notification wake mechanism, which starts the SilentBell app
   in the background for a short, bounded window (the design doc
   specifies ~30 seconds — long enough to pull one message, short
   enough to respect battery/OS background-execution limits).
4. **Pull, not push:** Once awake, User B's app is the one that
   initiates the next network request — it asks the DHT: "what's
   waiting in Queue X for me?" User A's device (or a DHT relay node
   holding the payload) responds with the actual encrypted message.
   This "pull" step is where the real payload transfers — the doorbell
   itself never carries content.
5. **Immediate cleanup:** After User B's device successfully retrieves
   and locally decrypts the payload, it asks the DHT/relay node to
   delete that payload from wherever it was staged. The message should
   not persist anywhere on the network after delivery — only on the
   two devices' local encrypted vaults.
6. **Back to sleep:** User B's app returns to its dormant state.

**Why "pull" instead of "push" for the payload itself:** if User A
could push data directly and unprompted, that data would need
somewhere to land while User B is asleep — meaning some intermediary
node is forced to buffer it, which starts to look like a mail server
the intermediary can be pressured to hand over. Making User B's device
the one that actively requests the payload (once briefly awake) keeps
the "who has custody of this data, and when" story simpler and
shorter-lived.

**Open implementation questions for whoever builds this:**
- Exact DHT node selection for "which peer relays the doorbell and
  holds the payload in the meantime" — not yet decided.
- What happens if the 30-second wake window expires before the pull
  completes (e.g. bad network) — retry logic not yet designed.
- Whether doorbell pings themselves need any anonymization (e.g. via
  Tor onion relay, per the original tech stack doc) or whether that's
  handled at the libp2p/transport layer instead.

## Protocol details: what "multi-layer encryption" means here

The phrase "multi-layer encryption" describes two DISTINCT encryption
boundaries in this system that must not be confused with each other —
they use different keys, protect against different threats, and exist
at different points in the data's lifecycle. Whoever implements the
P2P layer needs to keep these layers cleanly separated in code, not
collapse them into one "encrypt everything with one key" step.

**Layer 1 — Transport encryption (in transit, peer to peer/relay):**
- Protects a message while it's moving across the DHT — from User A's
  device, possibly through relay nodes, to User B's device.
- This is what `libp2p`'s built-in transport security (its `noise`
  protocol handshake, listed in the Cargo dependency comments) is for.
  Every hop on the network sees only Noise-encrypted traffic, not
  plaintext.
- Threat this defends against: a relay node or network observer
  reading message content in transit. It does NOT defend against the
  relay node knowing *that* two peers are communicating — metadata
  like "who's talking to whom" is a separate, harder problem (this is
  where the original doc's mention of Tor onion relaying would come
  in, if implemented — not yet decided).
- Key material: ephemeral, per-connection, negotiated by `libp2p`
  itself — not something this project generates or manages directly.

**Layer 2 — At-rest vault encryption (on-device, after delivery):**
- This is what `core/src/vault.rs` implements today. Once a message
  has been pulled and decrypted off the network, it needs to be
  re-encrypted before being written to the local SQLCipher database,
  so that a stolen/searched phone doesn't expose plaintext messages.
- Threat this defends against: physical device seizure/search — a
  completely different attacker than "someone sniffing network
  traffic," which is why it needs its own key (PIN-derived, per-device)
  completely independent of anything from Layer 1.
- This is also the layer that implements the real-PIN/duress-PIN
  deniability split — that concept has no equivalent at the transport
  layer; it's purely a property of local storage.

**A third, implicit layer — end-to-end message content encryption:**
The original design doc's tech stack table lists `libsignal-protocol`
alongside the transport and storage layers, implying that the message
*content itself* should be end-to-end encrypted with keys tied to the
sender/recipient identity keypairs (Layer 0, effectively) — independent
of both the transport encryption (which only protects hop-to-hop) and
the at-rest vault encryption (which only protects the local copy).
**This layer is not yet implemented or even scaffolded** — no
Signal-protocol-style double-ratchet or session key exchange exists in
this codebase yet. Flagging this explicitly because it's easy to
mistakenly assume Layer 1 (transport) or Layer 2 (vault) "covers"
end-to-end confidentiality — they don't. Without this layer, a
malicious or compromised relay node that also happens to be the DHT
node holding a payload could theoretically read it, since only
transport hop encryption (Layer 1) currently exists in the design.
This is the single most important missing piece before this system
could be called end-to-end encrypted in the way Signal or WhatsApp
use that term.


1. ~~Identity: keypair generation + Account ID derivation~~ (done)
2. ~~Vault: PIN-derived keys + silent-fail encryption~~ (mostly done,
   fixing a wiring bug)
3. Real SQLCipher-backed storage using the vault key (next milestone)
4. Decoy content generation strategy for duress vault
5. P2P layer: Kademlia DHT via `libp2p`, Queue ID negotiation
6. Doorbell/wake-up push mechanism (CoAP or UnifiedPush)
7. FFI boundary: expose `core`'s Rust functions to Kotlin
8. Minimal Kotlin/Flutter UI: generate identity, show Account ID,
   PIN entry screen
9. QR code / invitation link out-of-band connection UI
10. CI: GitHub Actions workflow to cross-compile and produce APKs,
    since the project owner's local hardware struggles with heavy
    builds

