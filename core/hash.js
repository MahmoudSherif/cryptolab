// hash.js — hash functions and message authentication codes.
//
// Covered:
//   Hashes: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256
//           SHA3-224, SHA3-256, SHA3-384, SHA3-512, Keccak-256
//           BLAKE2b, BLAKE2s, BLAKE3
//   MACs:   HMAC (over any of the above)
//           KMAC-128, KMAC-256
//           BLAKE3 keyed mode
//
// Web Crypto provides SHA-1/256/384/512 (and HMAC over those) natively;
// for SHA-3, BLAKE, and KMAC we fall through to noble-hashes.

(function (global) {
    'use strict';

    const NH = () => global.NobleHashes;

    // Map a canonical algorithm name to the noble function.
    function _hashFn(alg) {
        const map = {
            'sha-1':       () => NH().sha1,
            'sha-224':     () => NH().sha224,
            'sha-256':     () => NH().sha256,
            'sha-384':     () => NH().sha384,
            'sha-512':     () => NH().sha512,
            'sha-512/256': () => NH().sha512_256,
            'sha3-224':    () => NH().sha3_224,
            'sha3-256':    () => NH().sha3_256,
            'sha3-384':    () => NH().sha3_384,
            'sha3-512':    () => NH().sha3_512,
            'keccak-256':  () => NH().keccak_256,
            'blake2b':     () => NH().blake2b,
            'blake2s':     () => NH().blake2s,
            'blake3':      () => NH().blake3,
        };
        const k = alg.toLowerCase();
        if (!(k in map)) throw new Error('unsupported hash algorithm: ' + alg);
        return map[k]();
    }

    // List of all algorithms (used by UI to populate dropdowns).
    const HASH_ALGORITHMS = [
        'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-512/256',
        'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'Keccak-256',
        'BLAKE2b', 'BLAKE2s', 'BLAKE3',
    ];

    // ---------- hash ----------
    async function hash({ algorithm, data }) {
        if (!(data instanceof Uint8Array)) throw new TypeError('data must be Uint8Array');
        // Try Web Crypto first for the common ones (faster, native).
        const webCryptoMap = {
            'sha-1': 'SHA-1', 'sha-256': 'SHA-256',
            'sha-384': 'SHA-384', 'sha-512': 'SHA-512',
        };
        const wc = webCryptoMap[algorithm.toLowerCase()];
        if (wc && global.crypto && global.crypto.subtle) {
            const buf = await crypto.subtle.digest(wc, data);
            return { ok: true, output: new Uint8Array(buf),
                     params: { algorithm, outputBits: new Uint8Array(buf).length * 8 } };
        }
        const fn = _hashFn(algorithm);
        const out = fn(data);
        return { ok: true, output: out,
                 params: { algorithm, outputBits: out.length * 8 } };
    }

    // ---------- HMAC ----------
    async function hmac({ algorithm, key, data }) {
        if (!(key instanceof Uint8Array)) throw new TypeError('key must be Uint8Array');
        if (!(data instanceof Uint8Array)) throw new TypeError('data must be Uint8Array');
        // Web Crypto for SHA-1/256/384/512.
        const webCryptoMap = {
            'sha-1': 'SHA-1', 'sha-256': 'SHA-256',
            'sha-384': 'SHA-384', 'sha-512': 'SHA-512',
        };
        const wc = webCryptoMap[algorithm.toLowerCase()];
        if (wc && global.crypto && global.crypto.subtle) {
            const ck = await crypto.subtle.importKey('raw', key,
                { name: 'HMAC', hash: wc }, false, ['sign']);
            const buf = await crypto.subtle.sign('HMAC', ck, data);
            return { ok: true, output: new Uint8Array(buf),
                     params: { algorithm: `HMAC-${algorithm}`, keyBits: key.length * 8,
                               tagBits: new Uint8Array(buf).length * 8 } };
        }
        // noble HMAC takes (hash_function, key, data).
        const fn = _hashFn(algorithm);
        const out = NH().hmac(fn, key, data);
        return { ok: true, output: out,
                 params: { algorithm: `HMAC-${algorithm}`, keyBits: key.length * 8,
                           tagBits: out.length * 8 } };
    }

    // ---------- KMAC ----------
    function kmac({ variant, key, data, customization, outputBytes = 32 }) {
        if (!(key instanceof Uint8Array)) throw new TypeError('key must be Uint8Array');
        if (!(data instanceof Uint8Array)) throw new TypeError('data must be Uint8Array');
        const fn = variant === 256 ? NH().kmac256 : NH().kmac128;
        const opts = { dkLen: outputBytes };
        if (customization) opts.personalization = customization;
        const out = fn(key, data, opts);
        return { ok: true, output: out,
                 params: { algorithm: `KMAC-${variant}`, keyBits: key.length * 8,
                           outputBits: out.length * 8 } };
    }

    // ---------- BLAKE3 keyed mode ----------
    function blake3Keyed({ key, data, outputBytes = 32 }) {
        if (!(key instanceof Uint8Array) || key.length !== 32) {
            throw new Error('BLAKE3 keyed-mode key must be 32 bytes');
        }
        const out = NH().blake3(data, { key, dkLen: outputBytes });
        return { ok: true, output: out,
                 params: { algorithm: 'BLAKE3-keyed', keyBits: 256,
                           outputBits: out.length * 8 } };
    }

    // ---------- exports ----------
    global.cryptolab.hash = {
        hash, hmac, kmac, blake3Keyed,
        HASH_ALGORITHMS,
    };

})(typeof window !== 'undefined' ? window : globalThis);
