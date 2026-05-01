// symmetric.js — non-AEAD symmetric ciphers.
//
// Algorithms covered:
//   AES-128/192/256 in CBC, CTR, ECB modes
//   ChaCha20 (raw stream, no Poly1305 — that's in aead.js)
//
// All functions return:
//   { ok: true, output: Uint8Array, params: {...resolved parameters} }
//   { ok: false, error: 'human-readable message' }
//
// Parameters use Uint8Array for keys/IVs/data. Validation is strict —
// wrong key length, wrong IV length, or invalid padding all raise errors
// rather than silently truncating/extending.

(function (global) {
    'use strict';

    const { concatBytes } = global.cryptolab.encoding;

    // ---------- PKCS#7 padding ----------
    function pkcs7Pad(data, blockSize) {
        if (blockSize <= 0 || blockSize > 255) {
            throw new Error('blockSize out of range for PKCS#7');
        }
        const padLen = blockSize - (data.length % blockSize);
        const out = new Uint8Array(data.length + padLen);
        out.set(data);
        for (let i = data.length; i < out.length; i++) out[i] = padLen;
        return out;
    }

    function pkcs7Unpad(data, blockSize) {
        if (data.length === 0 || data.length % blockSize !== 0) {
            throw new Error('invalid padded length: ' + data.length);
        }
        const padLen = data[data.length - 1];
        if (padLen === 0 || padLen > blockSize) {
            throw new Error('invalid PKCS#7 padding byte: ' + padLen);
        }
        for (let i = data.length - padLen; i < data.length; i++) {
            if (data[i] !== padLen) {
                throw new Error('PKCS#7 padding bytes do not match');
            }
        }
        return data.subarray(0, data.length - padLen);
    }

    // ---------- AES key validation ----------
    function _validateAesKey(key) {
        if (!(key instanceof Uint8Array)) throw new TypeError('key must be Uint8Array');
        if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
            throw new Error(`AES key must be 16, 24, or 32 bytes (got ${key.length})`);
        }
        return key.length * 8;
    }

    // ---------- AES-CBC ----------
    async function aesCbc(op, { key, iv, data, padding = 'pkcs7' }) {
        const bits = _validateAesKey(key);
        if (!(iv instanceof Uint8Array) || iv.length !== 16) {
            throw new Error('AES-CBC IV must be 16 bytes');
        }
        if (op === 'encrypt') {
            const padded = padding === 'pkcs7' ? pkcs7Pad(data, 16)
                : padding === 'none' ? data
                : (() => { throw new Error('unknown padding: ' + padding); })();
            if (padding === 'none' && padded.length % 16 !== 0) {
                throw new Error('with padding=none, data length must be a multiple of 16');
            }
            const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
            // Web Crypto AES-CBC always applies PKCS#7. To support "no padding"
            // properly we use the noble fallback path.
            if (padding === 'none') {
                const out = global.NobleCiphers.aes.cbc(key, iv, { disablePadding: true }).encrypt(padded);
                return { ok: true, output: out, params: { algorithm: `AES-${bits}-CBC`, padding } };
            }
            // Web Crypto: it pads internally with PKCS#7. Pass raw data.
            const buf = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, ck, data);
            return { ok: true, output: new Uint8Array(buf),
                     params: { algorithm: `AES-${bits}-CBC`, padding: 'pkcs7' } };
        } else {
            const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
            if (padding === 'none') {
                const out = global.NobleCiphers.aes.cbc(key, iv, { disablePadding: true }).decrypt(data);
                return { ok: true, output: out, params: { algorithm: `AES-${bits}-CBC`, padding } };
            }
            const buf = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, ck, data);
            return { ok: true, output: new Uint8Array(buf),
                     params: { algorithm: `AES-${bits}-CBC`, padding: 'pkcs7' } };
        }
    }

    // ---------- AES-CTR ----------
    async function aesCtr(op, { key, nonce, data, counterBits = 64 }) {
        const bits = _validateAesKey(key);
        if (!(nonce instanceof Uint8Array) || nonce.length !== 16) {
            throw new Error('AES-CTR full counter block must be 16 bytes (nonce + counter combined)');
        }
        if (counterBits < 1 || counterBits > 128) {
            throw new Error('counterBits must be in [1, 128]');
        }
        const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, [op]);
        const buf = await crypto.subtle[op](
            { name: 'AES-CTR', counter: nonce, length: counterBits }, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: `AES-${bits}-CTR`, counterBits } };
    }

    // ---------- AES-ECB ----------
    // Educational only — never use in real code. Web Crypto refuses to
    // implement it, so we go through noble.
    async function aesEcb(op, { key, data, padding = 'pkcs7' }) {
        const bits = _validateAesKey(key);
        const cipher = global.NobleCiphers.aes.ecb(key, {
            disablePadding: padding === 'none',
        });
        const out = op === 'encrypt' ? cipher.encrypt(data) : cipher.decrypt(data);
        return { ok: true, output: out,
                 params: { algorithm: `AES-${bits}-ECB`, padding,
                           warning: 'ECB mode leaks plaintext patterns; do not use in production.' } };
    }

    // ---------- ChaCha20 (raw stream) ----------
    function chacha20(op, { key, nonce, data, counter = 0 }) {
        if (!(key instanceof Uint8Array) || key.length !== 32) {
            throw new Error('ChaCha20 key must be 32 bytes');
        }
        if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
            throw new Error('ChaCha20 nonce must be 12 bytes (IETF variant)');
        }
        // ChaCha20 is a stream cipher; encrypt and decrypt are the same op.
        const out = global.NobleCiphers.chacha20(key, nonce, data, counter);
        return { ok: true, output: out,
                 params: { algorithm: 'ChaCha20', counter } };
    }

    // ---------- generators ----------
    function generateAesKey(bits) {
        if (bits !== 128 && bits !== 192 && bits !== 256) {
            throw new Error('bits must be 128, 192, or 256');
        }
        return global.cryptolab.encoding.randomBytes(bits / 8);
    }

    // ---------- exports ----------
    global.cryptolab.symmetric = {
        aesCbc, aesCtr, aesEcb, chacha20,
        pkcs7Pad, pkcs7Unpad,
        generateAesKey,
    };

})(typeof window !== 'undefined' ? window : globalThis);
