// encoding.js — bytes ↔ hex / base64 / UTF-8 with auto-detection.
//
// All other code in cryptolab uses these for input parsing and output
// rendering. They're strict (reject malformed input with clear errors)
// and pure (no side effects, no I/O).

(function (global) {
    'use strict';

    // ---------- hex ----------
    function hexToBytes(s) {
        if (typeof s !== 'string') throw new TypeError('hexToBytes: not a string');
        // Tolerate common decorations: leading 0x/0X, whitespace, and ':' separators.
        s = s.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
        if (s.length === 0) return new Uint8Array(0);
        if (s.length % 2 !== 0) {
            throw new Error('hex string has odd length: ' + s.length);
        }
        if (!/^[0-9a-fA-F]*$/.test(s)) {
            const bad = s.match(/[^0-9a-fA-F]/);
            throw new Error('non-hex character in input: ' + JSON.stringify(bad[0]));
        }
        const out = new Uint8Array(s.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(s.substr(i * 2, 2), 16);
        }
        return out;
    }

    function bytesToHex(b) {
        if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
        let out = '';
        for (let i = 0; i < b.length; i++) {
            out += b[i].toString(16).padStart(2, '0');
        }
        return out;
    }

    // Pretty hex with optional spacing every N bytes.
    function bytesToHexPretty(b, groupSize = 0, separator = ' ') {
        const hex = bytesToHex(b);
        if (groupSize <= 0) return hex;
        const out = [];
        for (let i = 0; i < hex.length; i += groupSize * 2) {
            out.push(hex.slice(i, i + groupSize * 2));
        }
        return out.join(separator);
    }

    // ---------- base64 ----------
    // We use atob/btoa for browser compat. They work on binary strings
    // (each char = one byte), so we convert via Uint8Array.

    function bytesToBase64(b) {
        if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
        let s = '';
        for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
        return btoa(s);
    }

    function base64ToBytes(s) {
        if (typeof s !== 'string') throw new TypeError('base64ToBytes: not a string');
        s = s.replace(/\s/g, '');
        // Accept urlsafe base64 too.
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        // Re-pad if needed.
        while (s.length % 4 !== 0) s += '=';
        let bin;
        try {
            bin = atob(s);
        } catch (e) {
            throw new Error('invalid base64 input');
        }
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToBase64Url(b) {
        return bytesToBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // ---------- UTF-8 ----------
    const _enc = new TextEncoder();
    const _dec = new TextDecoder('utf-8', { fatal: false });
    const _decStrict = new TextDecoder('utf-8', { fatal: true });

    function utf8ToBytes(s) {
        return _enc.encode(s);
    }
    function bytesToUtf8(b, opts) {
        opts = opts || {};
        const dec = opts.strict ? _decStrict : _dec;
        return dec.decode(b);
    }

    // ---------- auto-detection ----------
    // Try to figure out which encoding a user-pasted string is. Used by the
    // input components so users don't have to manually pick a format.
    //
    // Heuristic order:
    //   1. If empty → empty bytes
    //   2. If looks like hex (only [0-9a-fA-F: \s_-], even length after cleanup) → hex
    //   3. If looks like base64 (only base64 alphabet incl. urlsafe, length % 4 == 0 or with padding)
    //      AND length is at least 4 → base64
    //   4. Otherwise → UTF-8
    //
    // We add an override knob for callers that already know.

    function detectEncoding(s) {
        if (s.length === 0) return 'utf8';
        const cleaned = s.replace(/[\s:_-]/g, '').replace(/^0x/i, '');
        if (cleaned.length > 0 && cleaned.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleaned)) {
            return 'hex';
        }
        const b64Cleaned = s.replace(/\s/g, '');
        if (b64Cleaned.length >= 4 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(b64Cleaned)) {
            // Base64-shaped. Disambiguate from short hex by length:
            // hex would have already matched above, so this is base64.
            // But a 4-char run of [a-f] is ambiguous — we prefer hex since
            // crypto inputs are more often hex.
            return 'base64';
        }
        return 'utf8';
    }

    function parseInput(s, encoding) {
        if (!encoding || encoding === 'auto') encoding = detectEncoding(s);
        switch (encoding) {
            case 'hex':    return { bytes: hexToBytes(s),    encoding };
            case 'base64': return { bytes: base64ToBytes(s), encoding };
            case 'utf8':   return { bytes: utf8ToBytes(s),   encoding };
            default: throw new Error('unknown encoding: ' + encoding);
        }
    }

    function formatBytes(b, encoding, opts) {
        opts = opts || {};
        switch (encoding) {
            case 'hex':       return bytesToHex(b);
            case 'hex-pretty': return bytesToHexPretty(b, opts.group || 4);
            case 'base64':    return bytesToBase64(b);
            case 'base64url': return bytesToBase64Url(b);
            case 'utf8':      return bytesToUtf8(b, opts);
            default: throw new Error('unknown encoding: ' + encoding);
        }
    }

    // ---------- numeric helpers ----------
    function bytesEqual(a, b) {
        if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
        if (a.length !== b.length) return false;
        // Constant-time-ish comparison for crypto outputs.
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function concatBytes(...arrays) {
        let total = 0;
        for (const a of arrays) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arrays) { out.set(a, off); off += a.length; }
        return out;
    }

    function randomBytes(n) {
        const out = new Uint8Array(n);
        // crypto.getRandomValues caps at 65536 bytes.
        for (let off = 0; off < n; off += 65536) {
            crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
        }
        return out;
    }

    // Deterministic PRNG seeded from a string. Useful for generating
    // reproducible test vectors. NOT cryptographically secure — this is
    // explicitly a deterministic substitute for randomness in tests.
    //
    // Implementation: SHA-256(seed || counter) produces a 32-byte chunk
    // per counter value. Suitable for test vectors, not for keys you
    // actually deploy.
    async function seededBytes(seed, n) {
        if (typeof seed === 'string') seed = utf8ToBytes(seed);
        const out = new Uint8Array(n);
        let off = 0, counter = 0;
        while (off < n) {
            const counterBytes = new Uint8Array(4);
            new DataView(counterBytes.buffer).setUint32(0, counter, false);
            const buf = await crypto.subtle.digest('SHA-256', concatBytes(seed, counterBytes));
            const chunk = new Uint8Array(buf);
            const take = Math.min(32, n - off);
            out.set(chunk.subarray(0, take), off);
            off += take;
            counter++;
        }
        return out;
    }

    // ---------- exports ----------
    global.cryptolab = global.cryptolab || {};
    global.cryptolab.encoding = {
        hexToBytes, bytesToHex, bytesToHexPretty,
        bytesToBase64, base64ToBytes, bytesToBase64Url,
        utf8ToBytes, bytesToUtf8,
        detectEncoding, parseInput, formatBytes,
        bytesEqual, concatBytes, randomBytes, seededBytes,
    };

})(typeof window !== 'undefined' ? window : globalThis);
