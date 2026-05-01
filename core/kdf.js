// kdf.js — key derivation functions.
//
// Covered:
//   PBKDF2 (HMAC-SHA-1/256/384/512)
//   HKDF   (extract + expand, over any hash)
//   scrypt (N, r, p)
//   Argon2id, Argon2i, Argon2d
//
// All return raw bytes of the requested length.

(function (global) {
    'use strict';

    const NH = () => global.NobleHashes;

    // ---------- PBKDF2 ----------
    async function pbkdf2({ password, salt, iterations, hash = 'SHA-256', dkLen = 32 }) {
        if (!(password instanceof Uint8Array)) throw new TypeError('password must be Uint8Array');
        if (!(salt instanceof Uint8Array)) throw new TypeError('salt must be Uint8Array');
        if (iterations < 1) throw new Error('iterations must be >= 1');
        if (dkLen < 1) throw new Error('dkLen must be >= 1');
        // Web Crypto for SHA-1/256/384/512.
        const wcHashes = { 'sha-1': 'SHA-1', 'sha-256': 'SHA-256',
                           'sha-384': 'SHA-384', 'sha-512': 'SHA-512' };
        const wc = wcHashes[hash.toLowerCase()];
        if (wc) {
            const ck = await crypto.subtle.importKey('raw', password,
                { name: 'PBKDF2' }, false, ['deriveBits']);
            const buf = await crypto.subtle.deriveBits(
                { name: 'PBKDF2', salt, iterations, hash: wc },
                ck, dkLen * 8);
            return { ok: true, output: new Uint8Array(buf),
                     params: { algorithm: `PBKDF2-HMAC-${hash}`,
                               iterations, saltLength: salt.length, dkLen } };
        }
        // Fall through to noble for SHA-3 etc.
        const hashFn = _resolveHash(hash);
        const out = NH().pbkdf2(hashFn, password, salt, { c: iterations, dkLen });
        return { ok: true, output: out,
                 params: { algorithm: `PBKDF2-HMAC-${hash}`,
                           iterations, saltLength: salt.length, dkLen } };
    }

    // ---------- HKDF ----------
    function hkdf({ ikm, salt, info, hash = 'SHA-256', dkLen = 32 }) {
        if (!(ikm instanceof Uint8Array)) throw new TypeError('ikm must be Uint8Array');
        salt = salt || new Uint8Array(0);
        info = info || new Uint8Array(0);
        const hashFn = _resolveHash(hash);
        const out = NH().hkdf(hashFn, ikm, salt, info, dkLen);
        return { ok: true, output: out,
                 params: { algorithm: `HKDF-${hash}`,
                           saltLength: salt.length, infoLength: info.length, dkLen } };
    }

    // ---------- scrypt ----------
    async function scrypt({ password, salt, N = 1 << 14, r = 8, p = 1, dkLen = 32, onProgress }) {
        if (!(password instanceof Uint8Array)) throw new TypeError('password must be Uint8Array');
        if (!(salt instanceof Uint8Array)) throw new TypeError('salt must be Uint8Array');
        if ((N & (N - 1)) !== 0 || N < 2) {
            throw new Error('scrypt N must be a power of 2 (>= 2)');
        }
        const opts = { N, r, p, dkLen };
        if (onProgress) opts.onProgress = onProgress;
        const out = NH().scrypt(password, salt, opts);
        return { ok: true, output: out,
                 params: { algorithm: 'scrypt', N, r, p, dkLen,
                           memoryMB: Math.round(128 * N * r / 1024 / 1024 * 100) / 100 } };
    }

    // ---------- Argon2 ----------
    // noble's argon2id takes (password, salt, opts).
    function argon2({ password, salt, variant = 'argon2id',
                      t = 3, m = 65536, p = 1, dkLen = 32 }) {
        if (!(password instanceof Uint8Array)) throw new TypeError('password must be Uint8Array');
        if (!(salt instanceof Uint8Array)) throw new TypeError('salt must be Uint8Array');
        if (salt.length < 8) throw new Error('Argon2 salt must be at least 8 bytes');
        const fn = variant === 'argon2i'  ? NH().argon2i
                 : variant === 'argon2d'  ? NH().argon2d
                 : NH().argon2id;
        const out = fn(password, salt, { t, m, p, dkLen });
        return { ok: true, output: out,
                 params: { algorithm: variant, t, m, p, dkLen,
                           memoryMB: Math.round(m / 1024 * 100) / 100 } };
    }

    function _resolveHash(name) {
        const k = name.toLowerCase();
        const map = {
            'sha-1':    NH().sha1,
            'sha-224':  NH().sha224,
            'sha-256':  NH().sha256,
            'sha-384':  NH().sha384,
            'sha-512':  NH().sha512,
            'sha3-224': NH().sha3_224,
            'sha3-256': NH().sha3_256,
            'sha3-384': NH().sha3_384,
            'sha3-512': NH().sha3_512,
        };
        if (!(k in map)) throw new Error('unsupported hash for KDF: ' + name);
        return map[k];
    }

    // ---------- exports ----------
    global.cryptolab.kdf = {
        pbkdf2, hkdf, scrypt, argon2,
    };

})(typeof window !== 'undefined' ? window : globalThis);
