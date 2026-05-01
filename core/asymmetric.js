// asymmetric.js — public-key cryptography.
//
// Covered:
//   RSA-OAEP (encrypt/decrypt) and RSA-PSS / RSASSA-PKCS1-v1_5 (sign/verify)
//     via Web Crypto
//   ECDSA over P-256, P-384, P-521 via Web Crypto
//   Ed25519 (sign/verify) via noble-curves
//   X25519 (key exchange) via noble-curves
//   secp256k1 (Bitcoin/Ethereum signing) via noble-curves
//
// Key formats:
//   RSA / ECDSA: SubjectPublicKeyInfo (DER) or PKCS#8 (DER) — what Web
//   Crypto's importKey accepts when format='spki'/'pkcs8'. We expose
//   raw export too for hex/b64 round trips.
//
//   Ed25519 / X25519 / secp256k1: raw bytes (32 for private,
//   32 / 33 / 65 for public depending on curve).

(function (global) {
    'use strict';

    const NC = () => global.NobleCurves;

    // ---------- RSA ----------
    async function generateRsaKeypair({ bits = 2048, hash = 'SHA-256', usage = 'oaep' }) {
        if (![1024, 2048, 3072, 4096].includes(bits)) {
            throw new Error('RSA bits must be 1024/2048/3072/4096');
        }
        const algo = usage === 'oaep'  ? { name: 'RSA-OAEP', hash, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) }
                   : usage === 'pss'   ? { name: 'RSA-PSS',  hash, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) }
                   : usage === 'pkcs1' ? { name: 'RSASSA-PKCS1-v1_5', hash, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) }
                   : (() => { throw new Error('usage must be oaep/pss/pkcs1'); })();
        const usages = (usage === 'oaep') ? ['encrypt', 'decrypt'] : ['sign', 'verify'];
        const kp = await crypto.subtle.generateKey(algo, true, usages);
        const pub  = new Uint8Array(await crypto.subtle.exportKey('spki',  kp.publicKey));
        const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
        return { ok: true, params: { algorithm: `RSA-${usage.toUpperCase()}`, bits, hash },
                 publicKey: pub, privateKey: priv };
    }

    async function rsaOaepEncrypt({ publicKey, hash = 'SHA-256', data, label }) {
        const ck = await crypto.subtle.importKey('spki', publicKey,
            { name: 'RSA-OAEP', hash }, false, ['encrypt']);
        const params = { name: 'RSA-OAEP' };
        if (label) params.label = label;
        const buf = await crypto.subtle.encrypt(params, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: 'RSA-OAEP', hash } };
    }
    async function rsaOaepDecrypt({ privateKey, hash = 'SHA-256', data, label }) {
        const ck = await crypto.subtle.importKey('pkcs8', privateKey,
            { name: 'RSA-OAEP', hash }, false, ['decrypt']);
        const params = { name: 'RSA-OAEP' };
        if (label) params.label = label;
        const buf = await crypto.subtle.decrypt(params, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: 'RSA-OAEP', hash } };
    }

    async function rsaPssSign({ privateKey, hash = 'SHA-256', data, saltLength = 32 }) {
        const ck = await crypto.subtle.importKey('pkcs8', privateKey,
            { name: 'RSA-PSS', hash }, false, ['sign']);
        const buf = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength }, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: 'RSA-PSS', hash, saltLength } };
    }
    async function rsaPssVerify({ publicKey, hash = 'SHA-256', data, signature, saltLength = 32 }) {
        const ck = await crypto.subtle.importKey('spki', publicKey,
            { name: 'RSA-PSS', hash }, false, ['verify']);
        const ok = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, ck, signature, data);
        return { ok: true, valid: ok, params: { algorithm: 'RSA-PSS', hash, saltLength } };
    }

    async function rsaPkcs1Sign({ privateKey, hash = 'SHA-256', data }) {
        const ck = await crypto.subtle.importKey('pkcs8', privateKey,
            { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign']);
        const buf = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: 'RSASSA-PKCS1-v1_5', hash } };
    }
    async function rsaPkcs1Verify({ publicKey, hash = 'SHA-256', data, signature }) {
        const ck = await crypto.subtle.importKey('spki', publicKey,
            { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
        const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, ck, signature, data);
        return { ok: true, valid: ok, params: { algorithm: 'RSASSA-PKCS1-v1_5', hash } };
    }

    // ---------- ECDSA (NIST P-curves) ----------
    async function generateEcdsaKeypair({ curve = 'P-256' }) {
        if (!['P-256', 'P-384', 'P-521'].includes(curve)) {
            throw new Error('curve must be P-256, P-384, or P-521');
        }
        const kp = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
        const pub  = new Uint8Array(await crypto.subtle.exportKey('spki',  kp.publicKey));
        const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
        return { ok: true, params: { algorithm: 'ECDSA', curve },
                 publicKey: pub, privateKey: priv };
    }

    async function ecdsaSign({ privateKey, curve = 'P-256', hash = 'SHA-256', data }) {
        const ck = await crypto.subtle.importKey('pkcs8', privateKey,
            { name: 'ECDSA', namedCurve: curve }, false, ['sign']);
        const buf = await crypto.subtle.sign({ name: 'ECDSA', hash }, ck, data);
        return { ok: true, output: new Uint8Array(buf),
                 params: { algorithm: 'ECDSA', curve, hash, format: 'IEEE P1363 (r||s, raw)' } };
    }

    async function ecdsaVerify({ publicKey, curve = 'P-256', hash = 'SHA-256', data, signature }) {
        const ck = await crypto.subtle.importKey('spki', publicKey,
            { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
        const ok = await crypto.subtle.verify({ name: 'ECDSA', hash }, ck, signature, data);
        return { ok: true, valid: ok, params: { algorithm: 'ECDSA', curve, hash } };
    }

    // ---------- Ed25519 ----------
    function generateEd25519Keypair() {
        const priv = global.cryptolab.encoding.randomBytes(32);
        const pub = NC().ed25519.getPublicKey(priv);
        return { ok: true, params: { algorithm: 'Ed25519' },
                 publicKey: pub, privateKey: priv };
    }
    function ed25519Sign({ privateKey, data }) {
        if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
            throw new Error('Ed25519 private key must be 32 bytes');
        }
        const sig = NC().ed25519.sign(data, privateKey);
        return { ok: true, output: sig,
                 params: { algorithm: 'Ed25519', signatureLength: sig.length } };
    }
    function ed25519Verify({ publicKey, data, signature }) {
        if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
            throw new Error('Ed25519 public key must be 32 bytes');
        }
        if (!(signature instanceof Uint8Array) || signature.length !== 64) {
            throw new Error('Ed25519 signature must be 64 bytes');
        }
        const ok = NC().ed25519.verify(signature, data, publicKey);
        return { ok: true, valid: ok, params: { algorithm: 'Ed25519' } };
    }

    // ---------- X25519 ----------
    function generateX25519Keypair() {
        const priv = global.cryptolab.encoding.randomBytes(32);
        const pub = NC().x25519.getPublicKey(priv);
        return { ok: true, params: { algorithm: 'X25519' },
                 publicKey: pub, privateKey: priv };
    }
    function x25519DeriveSharedSecret({ privateKey, peerPublicKey }) {
        if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
            throw new Error('X25519 private key must be 32 bytes');
        }
        if (!(peerPublicKey instanceof Uint8Array) || peerPublicKey.length !== 32) {
            throw new Error('X25519 public key must be 32 bytes');
        }
        const shared = NC().x25519.getSharedSecret(privateKey, peerPublicKey);
        return { ok: true, output: shared,
                 params: { algorithm: 'X25519', sharedSecretBytes: 32 } };
    }

    // ---------- secp256k1 (Bitcoin / Ethereum) ----------
    function generateSecp256k1Keypair() {
        const priv = NC().secp256k1.utils.randomPrivateKey();
        const pub = NC().secp256k1.getPublicKey(priv, true); // compressed
        return { ok: true, params: { algorithm: 'secp256k1', publicKeyFormat: 'compressed (33 B)' },
                 publicKey: pub, privateKey: priv };
    }
    function secp256k1Sign({ privateKey, msgHash }) {
        if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
            throw new Error('secp256k1 private key must be 32 bytes');
        }
        if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32) {
            throw new Error('secp256k1 message hash must be 32 bytes (hash your message first)');
        }
        const sig = NC().secp256k1.sign(msgHash, privateKey);
        return { ok: true, output: sig.toCompactRawBytes(),
                 params: { algorithm: 'secp256k1', signatureFormat: 'compact (r||s, 64 B)' } };
    }
    function secp256k1Verify({ publicKey, msgHash, signature }) {
        const ok = NC().secp256k1.verify(signature, msgHash, publicKey);
        return { ok: true, valid: ok, params: { algorithm: 'secp256k1' } };
    }

    // ---------- exports ----------
    global.cryptolab.asymmetric = {
        generateRsaKeypair, rsaOaepEncrypt, rsaOaepDecrypt,
        rsaPssSign, rsaPssVerify, rsaPkcs1Sign, rsaPkcs1Verify,
        generateEcdsaKeypair, ecdsaSign, ecdsaVerify,
        generateEd25519Keypair, ed25519Sign, ed25519Verify,
        generateX25519Keypair, x25519DeriveSharedSecret,
        generateSecp256k1Keypair, secp256k1Sign, secp256k1Verify,
    };

})(typeof window !== 'undefined' ? window : globalThis);
