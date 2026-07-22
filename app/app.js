/**
 * SofaMsg — Peer-to-peer encrypted messaging application
 * Client-side UI with Web Crypto API simulating the Rust core
 */

/* ═══════════════════════════════════════════════════════
   HELPER UTILITIES
   ═══════════════════════════════════════════════════════ */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode a Uint8Array to Base58 string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let result = '';
  for (const byte of bytes) {
    if (byte === 0) result += BASE58_ALPHABET[0];
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

/**
 * Format a timestamp as human-readable relative time
 * @param {number} timestamp - Unix milliseconds
 * @returns {string}
 */
function formatRelativeTime(timestamp) {
  const now = Date.now();
  const diff = now - timestamp;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

/**
 * Generate a deterministic avatar gradient from an account ID
 * @param {string} accountId
 * @returns {{gradient: string, initials: string}}
 */
function generateAvatar(accountId) {
  let hash = 0;
  for (let i = 0; i < accountId.length; i++) {
    hash = ((hash << 5) - hash + accountId.charCodeAt(i)) | 0;
  }
  const hue1 = Math.abs(hash % 360);
  const hue2 = (hue1 + 40 + Math.abs((hash >> 8) % 80)) % 360;
  const gradient = `linear-gradient(135deg, hsl(${hue1}, 70%, 50%), hsl(${hue2}, 80%, 40%))`;
  // Initials: take first 2 chars after sb_ prefix
  const clean = accountId.replace('sb_', '');
  const initials = clean.substring(0, 2).toUpperCase();
  return { gradient, initials };
}

/**
 * Escape HTML to prevent XSS
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Copy text to clipboard
 * @param {string} text
 * @returns {Promise<boolean>}
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  }
}

/**
 * Generate a QR-like placeholder pattern from account ID
 * @param {string} accountId
 * @param {number} size
 * @returns {string} SVG markup
 */
function generateQRPlaceholder(accountId, size = 160) {
  const grid = 11;
  const cellSize = size / grid;
  let hash = 0;
  for (let i = 0; i < accountId.length; i++) {
    hash = ((hash << 5) - hash + accountId.charCodeAt(i)) | 0;
  }
  let svg = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<rect width="${size}" height="${size}" fill="#1a1a2e" rx="8"/>`;
  for (let y = 0; y < grid; y++) {
    for (let x = 0; x < grid; x++) {
      const bit = ((hash >> ((x + y * grid) % 31)) ^ (x * y + hash)) & 1;
      if (bit) {
        svg += `<rect x="${x * cellSize + 1}" y="${y * cellSize + 1}" width="${cellSize - 2}" height="${cellSize - 2}" fill="#7c3aed" rx="2" opacity="0.8"/>`;
      }
    }
  }
  // Corner markers
  const markerSize = cellSize * 3;
  const drawMarker = (mx, my) => {
    svg += `<rect x="${mx}" y="${my}" width="${markerSize}" height="${markerSize}" fill="none" stroke="#a855f7" stroke-width="2" rx="3"/>`;
    svg += `<rect x="${mx + cellSize}" y="${my + cellSize}" width="${cellSize}" height="${cellSize}" fill="#a855f7" rx="1"/>`;
  };
  drawMarker(cellSize * 0.5, cellSize * 0.5);
  drawMarker(size - markerSize - cellSize * 0.5, cellSize * 0.5);
  drawMarker(cellSize * 0.5, size - markerSize - cellSize * 0.5);
  svg += '</svg>';
  return svg;
}

/**
 * Show a toast notification
 * @param {string} message
 * @param {'success'|'error'|'info'} type
 */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  const icons = {
    success: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };
  toast.innerHTML = `${icons[type] || icons.info}<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast--visible'));
  setTimeout(() => {
    toast.classList.remove('toast--visible');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}


/* ═══════════════════════════════════════════════════════
   CRYPTO ENGINE — Web Crypto stand-in for Rust core
   ═══════════════════════════════════════════════════════ */

class CryptoEngine {
  /**
   * Generate an ECDSA keypair (P-256 as Ed25519 stand-in)
   * @returns {Promise<{publicKeyRaw: Uint8Array, privateKeyJwk: object}>}
   */
  async generateKeypair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKeyRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey)
    );
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return { publicKeyRaw, privateKeyJwk };
  }

  /**
   * Derive an account ID from a public key (SHA-256 -> base58 -> sb_ prefix)
   * @param {Uint8Array} publicKeyRaw
   * @returns {Promise<string>}
   */
  async deriveAccountId(publicKeyRaw) {
    const hash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', publicKeyRaw)
    );
    return 'sb_' + base58Encode(hash);
  }

  /**
   * Derive a vault key from PIN + salt using PBKDF2 (Argon2id stand-in)
   * @param {string} pin
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async deriveVaultKey(pin, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(pin),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Export vault key as raw bytes (for hex display)
   * @param {string} pin
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async deriveVaultKeyExportable(pin, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(pin),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-CBC', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * AES-256-CBC encrypt with random IV
   * @param {CryptoKey} key
   * @param {string} plaintext
   * @returns {Promise<string>} base64-encoded IV+ciphertext
   */
  async encrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, encoded)
    );
    // Prepend IV
    const blob = new Uint8Array(iv.length + ciphertext.length);
    blob.set(iv);
    blob.set(ciphertext, iv.length);
    return btoa(String.fromCharCode(...blob));
  }

  /**
   * AES-256-CBC decrypt — returns garbage silently on wrong key (deniability)
   * @param {CryptoKey} key
   * @param {string} blob - base64-encoded IV+ciphertext
   * @returns {Promise<string>}
   */
  async decrypt(key, blob) {
    try {
      const raw = Uint8Array.from(atob(blob), c => c.charCodeAt(0));
      const iv = raw.slice(0, 16);
      const ciphertext = raw.slice(16);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch {
      // Silent fail — return garbage, not an error (deniability property)
      return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    }
  }
}


/* ═══════════════════════════════════════════════════════
   VAULT MANAGER — localStorage-backed encrypted storage
   ═══════════════════════════════════════════════════════ */

class VaultManager {
  constructor() {
    /** @type {CryptoEngine} */
    this.crypto = new CryptoEngine();
    /** @type {CryptoKey|null} */
    this.vaultKey = null;
    /** @type {object|null} */
    this.vaultData = null;
    /** @type {string|null} */
    this.accountId = null;
  }

  /** @returns {boolean} Whether a vault has been created */
  vaultExists() {
    return localStorage.getItem('sofamsg_vault') !== null;
  }

  /** @returns {boolean} */
  isUnlocked() {
    return this.vaultKey !== null && this.vaultData !== null;
  }

  /**
   * Create a new vault with a PIN
   * @param {string} pin - 6-digit PIN
   * @returns {Promise<{accountId: string}>}
   */
  async createVault(pin) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await this.crypto.deriveVaultKey(pin, salt);

    // Generate identity keypair
    const { publicKeyRaw, privateKeyJwk } = await this.crypto.generateKeypair();
    const accountId = await this.crypto.deriveAccountId(publicKeyRaw);

    // Create vault data structure
    const vaultData = {
      identity: {
        accountId,
        publicKeyRaw: btoa(String.fromCharCode(...publicKeyRaw)),
        privateKeyJwk,
      },
      conversations: {},
      createdAt: Date.now(),
    };

    // Encrypt and store
    const encrypted = await this.crypto.encrypt(key, JSON.stringify(vaultData));
    localStorage.setItem('sofamsg_vault', JSON.stringify({
      salt: btoa(String.fromCharCode(...salt)),
      data: encrypted,
    }));

    this.vaultKey = key;
    this.vaultData = vaultData;
    this.accountId = accountId;

    return { accountId };
  }

  /**
   * Unlock existing vault with PIN.
   * NEVER reveals whether PIN was wrong — returns true with possibly-garbage data.
   * @param {string} pin
   * @returns {Promise<boolean>}
   */
  async unlock(pin) {
    const stored = JSON.parse(localStorage.getItem('sofamsg_vault'));
    if (!stored) return false;

    const salt = Uint8Array.from(atob(stored.salt), c => c.charCodeAt(0));
    const key = await this.crypto.deriveVaultKey(pin, salt);

    const decrypted = await this.crypto.decrypt(key, stored.data);

    try {
      const parsed = JSON.parse(decrypted);
      if (parsed && parsed.identity && parsed.identity.accountId) {
        this.vaultKey = key;
        this.vaultData = parsed;
        this.accountId = parsed.identity.accountId;

        // Populate demo conversations on first unlock if empty
        if (Object.keys(this.vaultData.conversations).length === 0) {
          await this._populateDemoConversations();
        }

        return true;
      }
    } catch {
      // JSON parse failed — wrong PIN, silent fail
    }

    return false;
  }

  /** Lock the vault, clear in-memory state */
  lock() {
    this.vaultKey = null;
    this.vaultData = null;
    this.accountId = null;
  }

  /**
   * Save a message in the vault
   * @param {string} peerId
   * @param {string} body
   * @param {boolean} isOutgoing
   * @returns {Promise<object>} The saved message object
   */
  async saveMessage(peerId, body, isOutgoing) {
    if (!this.isUnlocked()) throw new Error('Vault locked');

    if (!this.vaultData.conversations[peerId]) {
      this.vaultData.conversations[peerId] = {
        peerId,
        peerName: peerId.substring(0, 12) + '...',
        messages: [],
      };
    }

    const message = {
      id: crypto.randomUUID(),
      body,
      isOutgoing,
      timestamp: Date.now(),
    };

    this.vaultData.conversations[peerId].messages.push(message);
    await this._persist();
    return message;
  }

  /**
   * Get messages for a peer
   * @param {string} peerId
   * @returns {object[]}
   */
  getMessages(peerId) {
    if (!this.isUnlocked()) return [];
    const convo = this.vaultData.conversations[peerId];
    return convo ? convo.messages : [];
  }

  /**
   * Get all conversations with last message preview
   * @returns {object[]}
   */
  getConversations() {
    if (!this.isUnlocked()) return [];
    return Object.values(this.vaultData.conversations).map(convo => {
      const lastMsg = convo.messages[convo.messages.length - 1];
      return {
        peerId: convo.peerId,
        peerName: convo.peerName,
        lastMessage: lastMsg ? lastMsg.body : '',
        lastTimestamp: lastMsg ? lastMsg.timestamp : 0,
        unread: 0,
      };
    }).sort((a, b) => b.lastTimestamp - a.lastTimestamp);
  }

  /**
   * Set a friendly name for a peer
   * @param {string} peerId
   * @param {string} name
   */
  async setPeerName(peerId, name) {
    if (this.vaultData.conversations[peerId]) {
      this.vaultData.conversations[peerId].peerName = name;
      await this._persist();
    }
  }

  /** Clear all vault data */
  clearAll() {
    localStorage.removeItem('sofamsg_vault');
    this.lock();
  }

  /** Persist vault data to localStorage (encrypted) */
  async _persist() {
    if (!this.vaultKey || !this.vaultData) return;
    const stored = JSON.parse(localStorage.getItem('sofamsg_vault'));
    const encrypted = await this.crypto.encrypt(this.vaultKey, JSON.stringify(this.vaultData));
    stored.data = encrypted;
    localStorage.setItem('sofamsg_vault', JSON.stringify(stored));
  }

  /** Populate demo conversations */
  async _populateDemoConversations() {
    const now = Date.now();
    const hour = 3600000;
    const minute = 60000;

    // Demo peer 1 — Alice
    const alice = 'sb_5dR7kM2pXvN8qLwT9fBzJcYhA3nE6gS4';
    this.vaultData.conversations[alice] = {
      peerId: alice,
      peerName: 'Alice',
      messages: [
        { id: crypto.randomUUID(), body: 'Hey! Have you tried the new SofaMsg app?', isOutgoing: false, timestamp: now - 4 * hour },
        { id: crypto.randomUUID(), body: 'Just got it set up! The encryption is solid.', isOutgoing: true, timestamp: now - 4 * hour + 2 * minute },
        { id: crypto.randomUUID(), body: 'Right? No servers, no registration. Just pure P2P.', isOutgoing: false, timestamp: now - 4 * hour + 5 * minute },
        { id: crypto.randomUUID(), body: 'The vault system with the duress PIN is brilliant. Real plausible deniability.', isOutgoing: true, timestamp: now - 3 * hour },
        { id: crypto.randomUUID(), body: 'Exactly. Even if someone forces you to unlock, they get the decoy vault. No way to prove the real one exists.', isOutgoing: false, timestamp: now - 3 * hour + 3 * minute },
      ],
    };

    // Demo peer 2 — Bob
    const bob = 'sb_8xF3nQ7wK4hY2mC6jR9pVbZeD5tL1aG';
    this.vaultData.conversations[bob] = {
      peerId: bob,
      peerName: 'Bob',
      messages: [
        { id: crypto.randomUUID(), body: 'Quick question about the key exchange mechanism', isOutgoing: false, timestamp: now - 24 * hour },
        { id: crypto.randomUUID(), body: 'Sure, what about it?', isOutgoing: true, timestamp: now - 24 * hour + minute },
        { id: crypto.randomUUID(), body: 'Is there a double ratchet for forward secrecy?', isOutgoing: false, timestamp: now - 24 * hour + 3 * minute },
        { id: crypto.randomUUID(), body: 'Not yet — that\'s the Signal protocol layer. It\'s on the roadmap but the transport encryption via libp2p noise is already there.', isOutgoing: true, timestamp: now - 23 * hour },
        { id: crypto.randomUUID(), body: 'Makes sense. Layer 1 for transport, Layer 2 for at-rest. Layer 0 E2E is next.', isOutgoing: false, timestamp: now - 23 * hour + 5 * minute },
        { id: crypto.randomUUID(), body: 'Exactly right. Each layer defends against different threats.', isOutgoing: true, timestamp: now - 22 * hour },
      ],
    };

    // Demo peer 3 — CryptoAnon
    const anon = 'sb_2vT9bH4rW6yU1sP8eN5mA3xQ7cJ0kD';
    this.vaultData.conversations[anon] = {
      peerId: anon,
      peerName: 'CryptoAnon',
      messages: [
        { id: crypto.randomUUID(), body: 'Is this truly serverless?', isOutgoing: false, timestamp: now - 48 * hour },
        { id: crypto.randomUUID(), body: 'Yes. Ed25519 keypairs generated locally, messages travel over DHT. No central point of failure or surveillance.', isOutgoing: true, timestamp: now - 47 * hour },
        { id: crypto.randomUUID(), body: 'What about the doorbell mechanism? Doesn\'t that need infrastructure?', isOutgoing: false, timestamp: now - 47 * hour + 10 * minute },
        { id: crypto.randomUUID(), body: 'The doorbell is just a tiny wake-up ping via CoAP or UnifiedPush — it carries zero content. The actual message is pulled by the receiver from DHT nodes.', isOutgoing: true, timestamp: now - 46 * hour },
        { id: crypto.randomUUID(), body: 'That\'s a solid design. Minimal attack surface.', isOutgoing: false, timestamp: now - 46 * hour + 2 * minute },
      ],
    };

    await this._persist();
  }
}


/* ═══════════════════════════════════════════════════════
   AUTO-REPLY ENGINE — Simulates P2P responses
   ═══════════════════════════════════════════════════════ */

const AUTO_REPLIES = [
  "That makes sense. The security model is well thought out.",
  "Agreed. Have you looked into the Kademlia DHT implementation?",
  "Nice! The Argon2id key derivation is the right choice over PBKDF2.",
  "True — the separate salts for real/duress vaults are critical for deniability.",
  "I'll check that out. The peer-to-peer architecture is really clean.",
  "Exactly. No central server means no single point of compromise.",
  "The AES-256-CBC without auth tag is intentional for silent-fail, right?",
  "That's a great point about the transport vs at-rest encryption layers.",
  "Have you tested the doorbell wake-up mechanism yet?",
  "The Ed25519 keys are much more compact than RSA for QR sharing.",
  "Sounds good! Let me know when you've got the next build ready.",
  "Interesting approach. The pull-based message retrieval is smart.",
  "I see what you mean. Forward secrecy will need the double ratchet layer.",
  "Yeah, the 30-second wake window should be enough for most connections.",
  "That's the beauty of it — even relay nodes can't read the content.",
];


/* ═══════════════════════════════════════════════════════
   UI CONTROLLER — All DOM interactions and screen flow
   ═══════════════════════════════════════════════════════ */

class UIController {
  constructor() {
    /** @type {VaultManager} */
    this.vault = new VaultManager();
    /** @type {string|null} */
    this.activeConversation = null;
    /** @type {boolean} */
    this.isCreatingPin = false;
    /** @type {string} */
    this.firstPin = '';
    /** @type {number[]} */
    this.autoReplyTimeouts = [];

    // DOM references
    this.els = {
      splash: document.getElementById('splash-screen'),
      pinScreen: document.getElementById('pin-screen'),
      pinTitle: document.getElementById('pin-title'),
      pinSubtitle: document.getElementById('pin-subtitle'),
      pinDigits: document.getElementById('pin-digits'),
      pinConfirmSection: document.getElementById('pin-confirm-section'),
      pinSubmit: document.getElementById('pin-submit'),
      pinStatus: document.getElementById('pin-status'),
      appLayout: document.getElementById('app-layout'),
      sidebar: document.getElementById('sidebar'),
      sidebarToggle: document.getElementById('sidebar-toggle'),
      sidebarOverlay: document.getElementById('sidebar-overlay'),
      userProfile: document.getElementById('user-profile'),
      userAvatar: document.getElementById('user-avatar'),
      userAccountId: document.getElementById('user-account-id'),
      newChatBtn: document.getElementById('new-chat-btn'),
      conversationList: document.getElementById('conversation-list'),
      chatArea: document.getElementById('chat-area'),
      chatEmpty: document.getElementById('chat-empty'),
      chatActive: document.getElementById('chat-active'),
      chatPeerAvatar: document.getElementById('chat-peer-avatar'),
      chatPeerName: document.getElementById('chat-peer-name'),
      chatPeerStatus: document.getElementById('chat-peer-status'),
      chatBackBtn: document.getElementById('chat-back-btn'),
      messageList: document.getElementById('message-list'),
      typingIndicator: document.getElementById('typing-indicator'),
      messageInput: document.getElementById('message-input'),
      sendBtn: document.getElementById('send-btn'),
      identityModal: document.getElementById('identity-modal'),
      identityClose: document.getElementById('identity-close'),
      identityAvatarLarge: document.getElementById('identity-avatar-large'),
      identityFullId: document.getElementById('identity-full-id'),
      identityCopy: document.getElementById('identity-copy'),
      identityQR: document.getElementById('identity-qr'),
      newChatModal: document.getElementById('new-chat-modal'),
      newChatClose: document.getElementById('new-chat-close'),
      peerIdInput: document.getElementById('peer-id-input'),
      startChatBtn: document.getElementById('start-chat-btn'),
      settingsOverlay: document.getElementById('settings-overlay'),
      settingsClose: document.getElementById('settings-close'),
      settingsBtn: document.getElementById('settings-btn'),
      clearVaultBtn: document.getElementById('clear-vault-btn'),
      lockBtn: document.getElementById('lock-btn'),
      lockBtnMobile: document.getElementById('lock-btn-mobile'),
      chatInfoBtn: document.getElementById('chat-info-btn'),
    };
  }

  /** Initialize the app */
  async init() {
    this._bindEvents();

    // Show splash for 1.5s, then transition to PIN screen
    setTimeout(() => {
      this.els.splash.classList.add('splash-screen--hide');
      setTimeout(() => {
        this.els.splash.classList.add('hidden');
        this._showPinScreen();
      }, 600);
    }, 1500);
  }

  /* ─── PIN SCREEN ─── */

  _showPinScreen() {
    this.els.pinScreen.classList.remove('hidden');
    this.els.pinScreen.classList.add('fade-in');

    if (!this.vault.vaultExists()) {
      this.isCreatingPin = true;
      this.els.pinTitle.textContent = 'Create PIN';
      this.els.pinSubtitle.textContent = 'Choose a 6-digit PIN to protect your vault';
      this.els.pinSubmit.querySelector('.btn-text').textContent = 'Create Vault';
    } else {
      this.isCreatingPin = false;
      this.els.pinTitle.textContent = 'Enter PIN';
      this.els.pinSubtitle.textContent = 'Enter your 6-digit PIN to unlock your vault';
      this.els.pinSubmit.querySelector('.btn-text').textContent = 'Unlock';
    }

    // Focus first digit
    const firstInput = this.els.pinDigits.querySelector('.pin-digit');
    if (firstInput) setTimeout(() => firstInput.focus(), 100);
  }

  _getPinValue() {
    const digits = this.els.pinDigits.querySelectorAll('.pin-digit');
    return Array.from(digits).map(d => d.value).join('');
  }

  _getConfirmPinValue() {
    const digits = this.els.pinConfirmSection.querySelectorAll('.pin-confirm');
    return Array.from(digits).map(d => d.value).join('');
  }

  _clearPinInputs(container = this.els.pinDigits) {
    container.querySelectorAll('.pin-digit').forEach(d => { d.value = ''; });
    const first = container.querySelector('.pin-digit');
    if (first) first.focus();
  }

  _shakePin() {
    const card = document.querySelector('.pin-card');
    card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 600);
    this._clearPinInputs();
    if (!this.isCreatingPin) {
      this.els.pinConfirmSection.classList.add('hidden');
    }
  }

  async _handlePinSubmit() {
    const pin = this._getPinValue();
    if (pin.length !== 6) return;

    if (this.isCreatingPin) {
      if (!this.firstPin) {
        // First entry — show confirm
        this.firstPin = pin;
        this.els.pinConfirmSection.classList.remove('hidden');
        const firstConfirm = this.els.pinConfirmSection.querySelector('.pin-confirm');
        if (firstConfirm) firstConfirm.focus();
        this.els.pinSubmit.disabled = true;
        return;
      }

      const confirmPin = this._getConfirmPinValue();
      if (confirmPin.length !== 6) return;

      if (pin !== confirmPin) {
        this._shakePin();
        this.firstPin = '';
        this._clearPinInputs(this.els.pinConfirmSection);
        this.els.pinConfirmSection.classList.add('hidden');
        showToast('PINs did not match. Try again.', 'error');
        return;
      }

      // Show loading
      this.els.pinSubmit.disabled = true;
      this.els.pinSubmit.querySelector('.btn-text').classList.add('hidden');
      this.els.pinSubmit.querySelector('.btn-loader').classList.remove('hidden');

      try {
        const { accountId } = await this.vault.createVault(pin);
        showToast('Vault created! Identity generated.', 'success');
        this._transitionToApp();
      } catch (err) {
        showToast('Failed to create vault.', 'error');
        this.els.pinSubmit.disabled = false;
        this.els.pinSubmit.querySelector('.btn-text').classList.remove('hidden');
        this.els.pinSubmit.querySelector('.btn-loader').classList.add('hidden');
      }
    } else {
      // Unlock existing vault
      this.els.pinSubmit.disabled = true;
      this.els.pinSubmit.querySelector('.btn-text').classList.add('hidden');
      this.els.pinSubmit.querySelector('.btn-loader').classList.remove('hidden');

      const success = await this.vault.unlock(pin);

      if (success) {
        this._transitionToApp();
      } else {
        // Silent fail — just shake, no error message (deniability)
        this._shakePin();
        this.els.pinSubmit.disabled = false;
        this.els.pinSubmit.querySelector('.btn-text').classList.remove('hidden');
        this.els.pinSubmit.querySelector('.btn-loader').classList.add('hidden');
      }
    }
  }

  /* ─── MAIN APP ─── */

  _transitionToApp() {
    this.els.pinScreen.classList.add('hidden');
    this.els.appLayout.classList.remove('hidden');
    this.els.appLayout.classList.add('fade-in');

    // Set user identity in sidebar
    const accountId = this.vault.accountId;
    this.els.userAccountId.textContent = accountId.substring(0, 16) + '...';
    this.els.userAccountId.title = accountId;

    const avatar = generateAvatar(accountId);
    this.els.userAvatar.style.background = avatar.gradient;
    this.els.userAvatar.textContent = avatar.initials;

    this._renderConversationList();
  }

  _renderConversationList() {
    const conversations = this.vault.getConversations();
    this.els.conversationList.innerHTML = '';

    if (conversations.length === 0) {
      this.els.conversationList.innerHTML = `
        <div class="conversation-empty">
          <p>No conversations yet.</p>
          <p class="dimmed">Start one with the button above.</p>
        </div>`;
      return;
    }

    for (const convo of conversations) {
      const avatar = generateAvatar(convo.peerId);
      const isActive = this.activeConversation === convo.peerId;
      const el = document.createElement('div');
      el.className = `conversation-item${isActive ? ' conversation-item--active' : ''}`;
      el.dataset.peerId = convo.peerId;
      el.innerHTML = `
        <div class="conversation-avatar" style="background: ${avatar.gradient}">${avatar.initials}</div>
        <div class="conversation-info">
          <div class="conversation-header-row">
            <span class="conversation-name">${escapeHtml(convo.peerName)}</span>
            <span class="conversation-time">${convo.lastTimestamp ? formatRelativeTime(convo.lastTimestamp) : ''}</span>
          </div>
          <div class="conversation-preview">
            <svg class="conversation-lock" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" opacity="0.4">
              <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span class="truncate">${escapeHtml(convo.lastMessage)}</span>
          </div>
        </div>
        ${convo.unread > 0 ? `<span class="badge">${convo.unread}</span>` : ''}`;
      el.addEventListener('click', () => this._openConversation(convo.peerId));
      this.els.conversationList.appendChild(el);
    }
  }

  _openConversation(peerId) {
    this.activeConversation = peerId;

    // Update sidebar selection
    this.els.conversationList.querySelectorAll('.conversation-item').forEach(el => {
      el.classList.toggle('conversation-item--active', el.dataset.peerId === peerId);
    });

    // Close sidebar on mobile
    this.els.sidebar.classList.remove('sidebar--open');
    this.els.sidebarOverlay.classList.remove('sidebar-overlay--visible');

    // Show chat area
    this.els.chatEmpty.classList.add('hidden');
    this.els.chatActive.classList.remove('hidden');
    this.els.chatActive.classList.add('fade-in');

    // Set peer header
    const convo = this.vault.vaultData.conversations[peerId];
    if (convo) {
      this.els.chatPeerName.textContent = convo.peerName;
      const avatar = generateAvatar(peerId);
      this.els.chatPeerAvatar.style.background = avatar.gradient;
      this.els.chatPeerAvatar.textContent = avatar.initials;
    }

    this._renderMessages(peerId);
    this.els.messageInput.focus();
  }

  _renderMessages(peerId) {
    const messages = this.vault.getMessages(peerId);
    this.els.messageList.innerHTML = '';

    let lastDate = '';
    for (const msg of messages) {
      const msgDate = new Date(msg.timestamp).toLocaleDateString();
      if (msgDate !== lastDate) {
        lastDate = msgDate;
        const divider = document.createElement('div');
        divider.className = 'message-date-divider';
        divider.innerHTML = `<span>${msgDate === new Date().toLocaleDateString() ? 'Today' : msgDate}</span>`;
        this.els.messageList.appendChild(divider);
      }

      const el = document.createElement('div');
      el.className = `message-bubble ${msg.isOutgoing ? 'message-bubble--sent' : 'message-bubble--received'}`;
      el.innerHTML = `
        <div class="message-body">${escapeHtml(msg.body)}</div>
        <div class="message-meta">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" opacity="0.5">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <span class="message-time">${formatRelativeTime(msg.timestamp)}</span>
        </div>`;
      this.els.messageList.appendChild(el);
    }

    // Scroll to bottom
    requestAnimationFrame(() => {
      this.els.messageList.scrollTop = this.els.messageList.scrollHeight;
    });
  }

  async _sendMessage() {
    const body = this.els.messageInput.value.trim();
    if (!body || !this.activeConversation) return;

    this.els.messageInput.value = '';
    this.els.messageInput.style.height = 'auto';
    this.els.sendBtn.disabled = true;

    const msg = await this.vault.saveMessage(this.activeConversation, body, true);
    this._renderMessages(this.activeConversation);
    this._renderConversationList();

    // Simulate auto-reply
    this._simulateReply(this.activeConversation);
  }

  _simulateReply(peerId) {
    // Show typing indicator after 0.5-1s
    const typingDelay = 500 + Math.random() * 500;
    const replyDelay = typingDelay + 1000 + Math.random() * 2000;

    const typingTimeout = setTimeout(() => {
      if (this.activeConversation === peerId) {
        this.els.typingIndicator.classList.remove('hidden');
        this.els.messageList.scrollTop = this.els.messageList.scrollHeight;
      }
    }, typingDelay);

    const replyTimeout = setTimeout(async () => {
      this.els.typingIndicator.classList.add('hidden');
      const reply = AUTO_REPLIES[Math.floor(Math.random() * AUTO_REPLIES.length)];
      await this.vault.saveMessage(peerId, reply, false);
      if (this.activeConversation === peerId) {
        this._renderMessages(peerId);
      }
      this._renderConversationList();
    }, replyDelay);

    this.autoReplyTimeouts.push(typingTimeout, replyTimeout);
  }

  /* ─── MODALS ─── */

  _showIdentityModal() {
    const accountId = this.vault.accountId;
    this.els.identityFullId.textContent = accountId;

    const avatar = generateAvatar(accountId);
    this.els.identityAvatarLarge.style.background = avatar.gradient;
    this.els.identityAvatarLarge.textContent = avatar.initials;

    this.els.identityQR.innerHTML = generateQRPlaceholder(accountId);

    this.els.identityModal.classList.remove('hidden');
    requestAnimationFrame(() => this.els.identityModal.classList.add('modal-overlay--visible'));
  }

  _hideIdentityModal() {
    this.els.identityModal.classList.remove('modal-overlay--visible');
    setTimeout(() => this.els.identityModal.classList.add('hidden'), 300);
  }

  _showNewChatModal() {
    this.els.newChatModal.classList.remove('hidden');
    requestAnimationFrame(() => this.els.newChatModal.classList.add('modal-overlay--visible'));
    this.els.peerIdInput.value = '';
    this.els.peerIdInput.focus();
  }

  _hideNewChatModal() {
    this.els.newChatModal.classList.remove('modal-overlay--visible');
    setTimeout(() => this.els.newChatModal.classList.add('hidden'), 300);
  }

  _showSettings() {
    this.els.settingsOverlay.classList.remove('hidden');
    requestAnimationFrame(() => this.els.settingsOverlay.classList.add('modal-overlay--visible'));
  }

  _hideSettings() {
    this.els.settingsOverlay.classList.remove('modal-overlay--visible');
    setTimeout(() => this.els.settingsOverlay.classList.add('hidden'), 300);
  }

  _startNewChat() {
    let peerId = this.els.peerIdInput.value.trim();
    if (!peerId) {
      showToast('Please enter a peer Account ID.', 'error');
      return;
    }
    if (!peerId.startsWith('sb_')) {
      peerId = 'sb_' + peerId;
    }
    this._hideNewChatModal();

    // Create the conversation if it doesn't exist
    if (!this.vault.vaultData.conversations[peerId]) {
      this.vault.vaultData.conversations[peerId] = {
        peerId,
        peerName: peerId.substring(0, 12) + '...',
        messages: [],
      };
      this.vault._persist();
    }

    this._renderConversationList();
    this._openConversation(peerId);
    showToast('Conversation started!', 'success');
  }

  _lockVault() {
    this.autoReplyTimeouts.forEach(t => clearTimeout(t));
    this.autoReplyTimeouts = [];
    this.activeConversation = null;
    this.vault.lock();
    this.firstPin = '';

    this.els.appLayout.classList.add('hidden');
    this.els.chatActive.classList.add('hidden');
    this.els.chatEmpty.classList.remove('hidden');
    this.els.messageList.innerHTML = '';
    this.els.conversationList.innerHTML = '';

    this._showPinScreen();
    this._clearPinInputs();
    showToast('Vault locked.', 'info');
  }

  /* ─── EVENT BINDING ─── */

  _bindEvents() {
    // PIN digit inputs
    const setupPinDigits = (container) => {
      const digits = container.querySelectorAll('.pin-digit');
      digits.forEach((input, idx) => {
        input.addEventListener('input', (e) => {
          const val = e.target.value.replace(/\D/g, '');
          e.target.value = val.slice(-1);
          if (val && idx < digits.length - 1) {
            digits[idx + 1].focus();
          }
          this._updatePinSubmitState();
        });
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Backspace' && !e.target.value && idx > 0) {
            digits[idx - 1].focus();
            digits[idx - 1].value = '';
          }
        });
        input.addEventListener('paste', (e) => {
          e.preventDefault();
          const paste = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
          paste.split('').forEach((ch, i) => {
            if (digits[i]) digits[i].value = ch;
          });
          if (paste.length > 0) digits[Math.min(paste.length, digits.length) - 1].focus();
          this._updatePinSubmitState();
        });
      });
    };
    setupPinDigits(this.els.pinDigits);
    setupPinDigits(this.els.pinConfirmSection);

    // PIN submit
    this.els.pinSubmit.addEventListener('click', () => this._handlePinSubmit());
    // Allow Enter key on PIN submit button
    this.els.pinSubmit.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this._handlePinSubmit();
    });

    // Sidebar toggle (mobile)
    this.els.sidebarToggle.addEventListener('click', () => {
      this.els.sidebar.classList.toggle('sidebar--open');
      this.els.sidebarOverlay.classList.toggle('sidebar-overlay--visible');
    });
    this.els.sidebarOverlay.addEventListener('click', () => {
      this.els.sidebar.classList.remove('sidebar--open');
      this.els.sidebarOverlay.classList.remove('sidebar-overlay--visible');
    });

    // Chat back button (mobile)
    this.els.chatBackBtn.addEventListener('click', () => {
      this.activeConversation = null;
      this.els.chatActive.classList.add('hidden');
      this.els.chatEmpty.classList.remove('hidden');
      this._renderConversationList();
      // On mobile, show sidebar
      if (window.innerWidth <= 768) {
        this.els.sidebar.classList.add('sidebar--open');
        this.els.sidebarOverlay.classList.add('sidebar-overlay--visible');
      }
    });

    // User profile → identity modal
    this.els.userProfile.addEventListener('click', () => this._showIdentityModal());
    this.els.identityClose.addEventListener('click', () => this._hideIdentityModal());
    this.els.identityModal.addEventListener('click', (e) => {
      if (e.target === this.els.identityModal) this._hideIdentityModal();
    });

    // Copy account ID
    this.els.identityCopy.addEventListener('click', async () => {
      const ok = await copyToClipboard(this.vault.accountId);
      if (ok) {
        this.els.identityCopy.querySelector('.copy-tooltip').classList.add('copy-tooltip--visible');
        setTimeout(() => {
          this.els.identityCopy.querySelector('.copy-tooltip').classList.remove('copy-tooltip--visible');
        }, 1500);
        showToast('Account ID copied!', 'success');
      }
    });

    // New chat
    this.els.newChatBtn.addEventListener('click', () => this._showNewChatModal());
    this.els.newChatClose.addEventListener('click', () => this._hideNewChatModal());
    this.els.newChatModal.addEventListener('click', (e) => {
      if (e.target === this.els.newChatModal) this._hideNewChatModal();
    });
    this.els.startChatBtn.addEventListener('click', () => this._startNewChat());
    this.els.peerIdInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this._startNewChat();
    });

    // Settings
    this.els.settingsBtn.addEventListener('click', () => this._showSettings());
    this.els.settingsClose.addEventListener('click', () => this._hideSettings());
    this.els.settingsOverlay.addEventListener('click', (e) => {
      if (e.target === this.els.settingsOverlay) this._hideSettings();
    });
    this.els.clearVaultBtn.addEventListener('click', () => {
      if (confirm('This will permanently delete all your data, keys, and messages. This cannot be undone. Continue?')) {
        this.vault.clearAll();
        this._hideSettings();
        this._lockVault();
        showToast('All data cleared.', 'info');
      }
    });

    // Lock buttons
    this.els.lockBtn.addEventListener('click', () => this._lockVault());
    this.els.lockBtnMobile.addEventListener('click', () => this._lockVault());

    // Message input
    this.els.messageInput.addEventListener('input', () => {
      this.els.sendBtn.disabled = !this.els.messageInput.value.trim();
      // Auto-resize
      this.els.messageInput.style.height = 'auto';
      this.els.messageInput.style.height = Math.min(this.els.messageInput.scrollHeight, 120) + 'px';
    });
    this.els.messageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this._sendMessage();
      }
    });
    this.els.sendBtn.addEventListener('click', () => this._sendMessage());

    // Chat info button
    this.els.chatInfoBtn.addEventListener('click', () => {
      if (!this.activeConversation) return;
      const convo = this.vault.vaultData.conversations[this.activeConversation];
      if (!convo) return;
      const msgCount = convo.messages.length;
      const truncId = convo.peerId.substring(0, 20) + '…';
      showToast(`Peer: ${truncId} · ${msgCount} message${msgCount !== 1 ? 's' : ''} · AES-256-CBC encrypted`, 'info');
    });

    // Browser back button
    window.addEventListener('popstate', () => {
      if (!this.els.identityModal.classList.contains('hidden')) {
        this._hideIdentityModal();
      } else if (!this.els.newChatModal.classList.contains('hidden')) {
        this._hideNewChatModal();
      } else if (!this.els.settingsOverlay.classList.contains('hidden')) {
        this._hideSettings();
      }
    });
  }

  _updatePinSubmitState() {
    const pin = this._getPinValue();
    if (this.isCreatingPin && this.firstPin) {
      const confirmPin = this._getConfirmPinValue();
      this.els.pinSubmit.disabled = confirmPin.length !== 6;
    } else {
      this.els.pinSubmit.disabled = pin.length !== 6;
    }
  }
}


/* ═══════════════════════════════════════════════════════
   APP INITIALIZATION
   ═══════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  const app = new UIController();
  app.init();
});
