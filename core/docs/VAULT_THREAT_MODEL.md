# Vault Threat Model

**Read this before modifying `vault.rs`.**

## What this document covers

The local vault encryption in `vault.rs` deliberately uses **AES-256-CBC
without an authentication tag** (no GCM, no HMAC). This is NOT a missing
best-practice — it is the mechanism that makes the silent-fail /
plausible-deniability property possible.

## The threat: coerced unlock

The primary threat this layer defends against is **physical device seizure
with coerced PIN disclosure** — an attacker who has the device and can
force the user to provide a PIN, but cannot determine whether the PIN
they received was the "real" one or the "duress" one.

## Why no authentication tag

### With an auth tag (e.g., AES-256-GCM)

Decryption of the vault with a wrong key fails explicitly: GCM returns
an authentication error. This means:

- An attacker who tries 10 PINs and gets 9 auth failures + 1 success
  **knows which PIN was correct**.
- If the user provides a duress PIN and it decrypts successfully to the
  decoy vault, the attacker can then try other PINs — any PIN that also
  decrypts successfully (the real vault) is immediately distinguishable
  from wrong PINs that fail authentication.
- The existence of a second valid PIN (and therefore a second vault) is
  **provable** through brute force over the small PIN space.

### Without an auth tag (AES-256-CBC, our choice)

Decryption with **any** key always produces **some** output:

- A correct key produces valid JSON (the vault data).
- A wrong key produces random-looking garbage bytes.
- **Crucially:** there is no cryptographic signal distinguishing "correct
  but unexpected" output from "incorrect" output. The only way to tell
  is to parse the output and see if it's valid JSON with the expected
  schema — which the application does internally, but an external
  observer cannot distinguish a "wrong key produced garbage" from
  "wrong key produced a valid but empty/duress vault" without knowing
  the expected format.

This means:

1. The real vault decrypts to real messages.
2. The duress vault (encrypted with a separate salt + the duress PIN)
   decrypts to innocuous decoy messages.
3. Any other PIN decrypts the real vault's ciphertext to garbage — but
   **does not error out**. The app silently shows an empty/decoy state.
4. An attacker cannot distinguish case 2 from case 3 without already
   knowing the real PIN.

## What this does NOT protect against

- **Padding oracle attacks**: Without an auth tag, CBC is theoretically
  vulnerable to padding oracle attacks if the application leaks timing
  or error information about PKCS7 unpadding. Mitigation: `decrypt()`
  in `vault.rs` returns the output in **both** the valid-padding and
  invalid-padding cases — it never reports a padding error to any
  external interface. Invalid padding just means the raw (possibly
  garbage) buffer is returned as-is.

- **Ciphertext malleability**: An attacker with write access to the
  encrypted vault file could flip bits in the ciphertext, and the
  modified data would decrypt without error (to different garbage).
  Mitigation: this is a local-only file on a device the user physically
  controls. If an attacker has write access to the device filesystem,
  they have larger problems. File-level integrity is delegated to the
  OS / filesystem.

- **Brute force over the PIN space**: A 6-digit PIN has only 10^6
  possible values. Argon2id with the chosen parameters makes each
  attempt take ~200ms on modern hardware, so the full space is
  searchable in ~55 hours. This is a known limitation accepted in
  exchange for usability (users won't memorize a 20-character
  passphrase). The deniability property means brute force finds *a*
  valid PIN but cannot prove whether it's the real one or the duress
  one.

## Design invariants (do not break these)

1. `decrypt()` must **never** return an error that distinguishes "wrong
   key" from "correct key with unexpected data." Both cases must return
   `Vec<u8>` output.

2. The real vault and duress vault must use **separate random salts**,
   generated independently. Reusing one salt for both would allow an
   attacker to derive both keys from the same salt + two PINs and
   prove that two vaults exist.

3. The IV must be **random per encryption**, prepended to the
   ciphertext blob. Never reuse an IV.

4. Key derivation must use Argon2id (not PBKDF2, not bcrypt) per OWASP
   current recommendations.

## Summary

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality at rest | ✅ | AES-256-CBC, Argon2id KDF |
| Plausible deniability | ✅ | Silent-fail decrypt, dual vault |
| Integrity/authenticity | ❌ Intentionally omitted | Would break deniability |
| Padding oracle resistance | ✅ Mitigated | No error differentiation |
| Brute-force resistance | ⚠️ Limited | 10^6 PIN space, ~55h exhaustive |
