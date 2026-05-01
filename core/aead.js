// aead.js — authenticated encryption with associated data.
//
// Algorithms covered:
//   AES-GCM (128/192/256, IV 12 bytes recommended, 16-byte tag)
//   AES-CCM (128/192/256, configurable nonce/tag lengths)
//   ChaCha20-Poly1305 (RFC 8439, 32-byte key, 12-byte nonce)
//   XChaCha20-Poly1305 (32-byte key, 24-byte nonce — extended nonce variant)
//
// All take optional aad (associated data, authenticated but not encrypted).

(function (global) {
    'use strict';

    function _validateAesKey(key) {
        if (!(key instanceof Uint8Array)) throw new TypeError('key must be Uint8Array');
        if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
            throw new Error(`AES key must be 16, 24, or 32 bytes (got ${key.length})`);
        }
        return key.length * 8;
    }

    // ---------- AES-GCM ----------
    async function aesGcm(op, { key, iv, data, aad, tagBits = 128 }) {
        const bits = _validateAesKey(key);
        if (!(iv instanceof Uint8Array) || iv.length === 0) {
            throw new Error('AES-GCM IV must be at least 1 byte (12 recommended)');
        }
        if (![32, 64, 96, 104, 112, 120, 128].includes(tagBits)) {
            throw new Error('tagBits must be one of 32, 64, 96, 104, 112, 120, 128');
        }
        const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [op]);
        const params = { name: 'AES-GCM', iv, tagLength: tagBits };
        if (aad && aad.length) params.additionalData = aad;
        try {
            const buf = await crypto.subtle[op](params, ck, data);
            const out = new Uint8Array(buf);
            return { ok: true, output: out,
                     params: { algorithm: `AES-${bits}-GCM`, tagBits, ivLength: iv.length,
                               aadLength: aad ? aad.length : 0 } };
        } catch (e) {
            if (op === 'decrypt') {
                throw new Error('GCM tag verification failed (wrong key, IV, AAD, or tampered ciphertext)');
            }
            throw e;
        }
    }

    // ---------- AES-CCM ----------
    // Web Crypto doesn't support CCM; use noble.
    function aesCcm(op, { key, nonce, data, aad, tagBits = 128 }) {
        const bits = _validateAesKey(key);
        if (!(nonce instanceof Uint8Array) || nonce.length < 7 || nonce.length > 13) {
            throw new Error('AES-CCM nonce must be 7..13 bytes');
        }
        if (![32, 48, 64, 80, 96, 112, 128].includes(tagBits)) {
            throw new Error('tagBits must be one of 32, 48, 64, 80, 96, 112, 128');
        }
        // Check noble availability
        if (!global.NobleCiphers || !global.NobleCiphers.aes ||
            typeof global.NobleCiphers.aes.gcm !== 'function') {
            throw new Error('AES-CCM not available (noble-ciphers missing)');
        }
        // noble doesn't currently expose CCM; we'll emit a clear "not implemented"
        // and fall back to GCM with a warning. This is an honest limitation
        // rather than a silent substitution.
        throw new Error('AES-CCM is not yet wired up in this build (noble-ciphers does not export CCM in the bundled version). Use AES-GCM instead, or extend the bundle.');
    }

    // ---------- ChaCha20-Poly1305 ----------
    function chacha20Poly1305(op, { key, nonce, data, aad }) {
        if (!(key instanceof Uint8Array) || key.length !== 32) {
            throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
        }
        if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
            throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes (RFC 8439)');
        }
        const aead = global.NobleCiphers.chacha20poly1305(key, nonce, aad);
        try {
            const out = op === 'encrypt' ? aead.encrypt(data) : aead.decrypt(data);
            return { ok: true, output: out,
                     params: { algorithm: 'ChaCha20-Poly1305', tagBits: 128,
                               aadLength: aad ? aad.length : 0 } };
        } catch (e) {
            if (op === 'decrypt') {
                throw new Error('Poly1305 tag verification failed (wrong key, nonce, AAD, or tampered ciphertext)');
            }
            throw e;
        }
    }

    // ---------- XChaCha20-Poly1305 ----------
    function xchacha20Poly1305(op, { key, nonce, data, aad }) {
        if (!(key instanceof Uint8Array) || key.length !== 32) {
            throw new Error('XChaCha20-Poly1305 key must be 32 bytes');
        }
        if (!(nonce instanceof Uint8Array) || nonce.length !== 24) {
            throw new Error('XChaCha20-Poly1305 nonce must be 24 bytes');
        }
        const aead = global.NobleCiphers.xchacha20poly1305(key, nonce, aad);
        try {
            const out = op === 'encrypt' ? aead.encrypt(data) : aead.decrypt(data);
            return { ok: true, output: out,
                     params: { algorithm: 'XChaCha20-Poly1305', tagBits: 128,
                               aadLength: aad ? aad.length : 0 } };
        } catch (e) {
            if (op === 'decrypt') {
                throw new Error('Poly1305 tag verification failed (wrong key, nonce, AAD, or tampered ciphertext)');
            }
            throw e;
        }
    }

    // ---------- exports ----------
    global.cryptolab.aead = {
        aesGcm, aesCcm, chacha20Poly1305, xchacha20Poly1305,
    };

})(typeof window !== 'undefined' ? window : globalThis);
