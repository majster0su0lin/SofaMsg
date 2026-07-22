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

**Done and tested (110 tests passing across core, p2p, and ffi):**
- `keys.rs` — `Keypair::generate()` using OS entropy (`OsRng`), Ed25519 via `ed25519-dalek`.
- `identity.rs` — `derive_account_id()`, SHA-256 of the public key, base58-encoded with an `sb_` prefix.
- `vault.rs` — `derive_key()` (Argon2id, PIN + salt -> 256-bit key), `encrypt()`/`decrypt()` (AES-256-CBC, no auth tag for silent-fail plausible deniability).
- `storage.rs` — SQLCipher-backed local encrypted database, CRUD message operations, and chaff block generator (`pad_chaff()`) to equalize DB file sizes between real and duress vaults.
- `decoy.rs` — Deterministic, plausible decoy conversation generation for duress PIN unlocks.
- `e2e/` — Signal-style Extended Triple Diffie-Hellman (X3DH) + Double Ratchet with AES-256-GCM authenticated encryption for end-to-end message confidentiality & integrity.
- `p2p/` — Kademlia DHT networking via `libp2p` (TCP + Noise transport), Queue ID derivation, and message envelope payload staging.
- `doorbell.rs` — CoAP (UDP) & UnifiedPush (HTTP) wake-up ping mechanism with nonces and timestamp freshness validation.
- `invite.rs` — `sofamsg://connect` URIs and binary QR code payload generator/parser with account ID tampering validation.
- `ffi/` — Complete Mozilla UniFFI bindings layer exposing identity, vault, encrypted storage, chaffing, decoy content, invitations, and Queue IDs to Kotlin / Swift.
- `.github/workflows/ci.yml` — Automated CI workflow cross-compiling Rust `cdylib` with `cargo-ndk` across `arm64-v8a`, `armeabi-v7a`, `x86_64` and building Android APKs.

**Milestones Completed & Next Steps:**

1. ~~Identity: keypair generation + Account ID derivation~~ (done)
2. ~~Vault: PIN-derived keys + silent-fail encryption~~ (done)
3. ~~Real SQLCipher-backed storage using the vault key + chaffing~~ (done)
4. ~~Decoy content generation strategy for duress vault~~ (done)
5. ~~Layer 0 E2E Encryption: X3DH + Double Ratchet~~ (done)
6. ~~P2P layer: Kademlia DHT via libp2p, Queue ID routing~~ (done)
7. ~~Doorbell/wake-up push mechanism (CoAP & UnifiedPush)~~ (done)
8. ~~Out-of-band invitation mechanism (QR code & sofamsg:// URIs)~~ (done)
9. ~~FFI boundary: complete UniFFI bridge for Kotlin/Android & generated sofamsg.kt bindings~~ (done)
10. ~~CI: GitHub Actions workflow for cross-compilation & APK builds~~ (done)
11. ~~Mobile Client Integration: SofaMsgCoreManager & Jetpack Compose UI vault/storage integration~~ (done)

