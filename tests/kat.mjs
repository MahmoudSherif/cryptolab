// kat.mjs — known-answer tests against published vectors.
// Run with: node tests/kat.mjs

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Set up a browser-like context.
const ctx = {
    console, crypto: globalThis.crypto, TextEncoder, TextDecoder,
    Uint8Array, btoa, atob, DataView, ArrayBuffer, Promise, Math,
    Object, Array, Error, TypeError, JSON, Symbol, parseInt,
    setTimeout, clearTimeout, performance,
};
ctx.globalThis = ctx;
ctx.window = ctx;
vm.createContext(ctx);

// Load order matters.
for (const f of [
    'vendor/noble-hashes.js', 'vendor/noble-curves.js', 'vendor/noble-ciphers.js',
    'core/encoding.js', 'core/symmetric.js', 'core/aead.js',
    'core/hash.js', 'core/kdf.js', 'core/asymmetric.js',
]) {
    vm.runInContext(readFileSync(resolve(ROOT, f), 'utf8'), ctx, { filename: f });
}

const cl = ctx.cryptolab;
const { hexToBytes, bytesToHex, utf8ToBytes } = cl.encoding;

let pass = 0, fail = 0;
function check(label, ok, info = '') {
    if (ok) { console.log('  ✓', label); pass++; }
    else    { console.log('  ✗', label, info ? '\n      ' + info : ''); fail++; }
}
async function expectHex(label, promise, expected) {
    try {
        const res = await promise;
        const got = bytesToHex(res.output);
        check(label + ' = ' + got.slice(0, 16) + '...', got === expected.toLowerCase(),
              got === expected.toLowerCase() ? '' : `expected ${expected}\n      actual   ${got}`);
    } catch (e) { check(label, false, 'threw: ' + e.message); }
}

// -------------------------------------------------------------
console.log('\n=== SHA-256 / SHA-3 / SHA-512 (FIPS 180-4 / 202) ===');
await expectHex('SHA-256("abc")',
    cl.hash.hash({ algorithm: 'SHA-256', data: utf8ToBytes('abc') }),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
await expectHex('SHA-256("")',
    cl.hash.hash({ algorithm: 'SHA-256', data: utf8ToBytes('') }),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
await expectHex('SHA-512("abc")',
    cl.hash.hash({ algorithm: 'SHA-512', data: utf8ToBytes('abc') }),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
    '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
await expectHex('SHA3-256("abc")',
    cl.hash.hash({ algorithm: 'SHA3-256', data: utf8ToBytes('abc') }),
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');

// -------------------------------------------------------------
console.log('\n=== HMAC (RFC 4231) ===');
// RFC 4231 test case 1: key=20*0x0b, data="Hi There"
await expectHex('HMAC-SHA-256 (RFC 4231 #1)',
    cl.hash.hmac({
        algorithm: 'SHA-256',
        key: new Uint8Array(20).fill(0x0b),
        data: utf8ToBytes('Hi There'),
    }),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

await expectHex('HMAC-SHA-512 (RFC 4231 #1)',
    cl.hash.hmac({
        algorithm: 'SHA-512',
        key: new Uint8Array(20).fill(0x0b),
        data: utf8ToBytes('Hi There'),
    }),
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
    'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');

// -------------------------------------------------------------
console.log('\n=== AES-GCM (NIST SP 800-38D) ===');
// "Test Case 3" from the GCM spec: 96-bit IV.
await expectHex('AES-128-GCM ciphertext (NIST TC3)',
    cl.aead.aesGcm('encrypt', {
        key:  hexToBytes('feffe9928665731c6d6a8f9467308308'),
        iv:   hexToBytes('cafebabefacedbaddecaf888'),
        data: hexToBytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
                         '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'),
    }),
    '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985' +
    '4d5c2af327cd64a62cf35abd2ba6fab4');  // includes 16-byte tag

// -------------------------------------------------------------
console.log('\n=== AES-CBC ===');
// NIST SP 800-38A example: AES-128-CBC, key=2b7e1516..., iv=000102...
// First two blocks of plaintext.
await expectHex('AES-128-CBC encrypt (NIST F.2.1)',
    cl.symmetric.aesCbc('encrypt', {
        key:     hexToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
        iv:      hexToBytes('000102030405060708090a0b0c0d0e0f'),
        data:    hexToBytes('6bc1bee22e409f96e93d7e117393172a' +
                            'ae2d8a571e03ac9c9eb76fac45af8e51'),
        padding: 'none',
    }),
    '7649abac8119b246cee98e9b12e9197d' +
    '5086cb9b507219ee95db113a917678b2');

// -------------------------------------------------------------
console.log('\n=== ChaCha20-Poly1305 (RFC 8439 §2.8.2) ===');
const rfcKey   = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
const rfcNonce = hexToBytes('070000004041424344454647');
const rfcAad   = hexToBytes('50515253c0c1c2c3c4c5c6c7');
const rfcPt    = utf8ToBytes(
    "Ladies and Gentlemen of the class of '99: If I could offer you " +
    "only one tip for the future, sunscreen would be it.");
await expectHex('ChaCha20-Poly1305 encrypt (RFC 8439)',
    cl.aead.chacha20Poly1305('encrypt', {
        key: rfcKey, nonce: rfcNonce, data: rfcPt, aad: rfcAad,
    }),
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
    '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
    '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
    '3ff4def08e4b7a9de576d26586cec64b6116' +
    '1ae10b594f09e26a7e902ecbd0600691');  // tag

// -------------------------------------------------------------
console.log('\n=== PBKDF2 (RFC 6070) ===');
// RFC 6070 vector: P="password", S="salt", c=2, dkLen=20, HMAC-SHA-1.
await expectHex('PBKDF2-HMAC-SHA-1 (RFC 6070 #2)',
    cl.kdf.pbkdf2({
        password: utf8ToBytes('password'),
        salt:     utf8ToBytes('salt'),
        iterations: 2, hash: 'SHA-1', dkLen: 20,
    }),
    'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');

// -------------------------------------------------------------
console.log('\n=== HKDF (RFC 5869) ===');
// Test Case 1.
{
    const res = cl.kdf.hkdf({
        ikm:  hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
        salt: hexToBytes('000102030405060708090a0b0c'),
        info: hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
        hash: 'SHA-256', dkLen: 42,
    });
    const got = bytesToHex(res.output);
    const expected = '3cb25f25faacd57a90434f64d0362f2a' +
                     '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
                     '34007208d5b887185865';
    check('HKDF-SHA-256 (RFC 5869 TC1)', got === expected,
          got === expected ? '' : `expected ${expected}\n      actual   ${got}`);
}

// -------------------------------------------------------------
console.log('\n=== scrypt (RFC 7914) ===');
// RFC 7914 §11 first test vector: "" / "" / N=16, r=1, p=1, dkLen=64.
await expectHex('scrypt(N=16, r=1, p=1) RFC 7914 #1',
    cl.kdf.scrypt({
        password: utf8ToBytes(''),
        salt:     utf8ToBytes(''),
        N: 16, r: 1, p: 1, dkLen: 64,
    }),
    '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442' +
    'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');

// -------------------------------------------------------------
console.log('\n=== Ed25519 (RFC 8032 §7.1) ===');
// Test 1: empty message, all-zero-ish key.
{
    const sk = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const expectedPk  = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    const expectedSig = 'e5564300c360ac729086e2cc806e828a' +
                        '84877f1eb8e5d974d873e06522490155' +
                        '5fb8821590a33bacc61e39701cf9b46b' +
                        'd25bf5f0595bbe24655141438e7a100b';
    const pk = ctx.NobleCurves.ed25519.getPublicKey(sk);
    check('Ed25519 public key derivation', bytesToHex(pk) === expectedPk);
    const sig = cl.asymmetric.ed25519Sign({ privateKey: sk, data: new Uint8Array(0) });
    check('Ed25519 sign empty msg', bytesToHex(sig.output) === expectedSig);
    const v = cl.asymmetric.ed25519Verify({ publicKey: pk, data: new Uint8Array(0), signature: sig.output });
    check('Ed25519 verify',  v.valid === true);
}

// -------------------------------------------------------------
console.log('\n=== X25519 (RFC 7748 §6.1) ===');
{
    // Alice's private key.
    const a = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    // Bob's public key.
    const B = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const expected = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    const res = cl.asymmetric.x25519DeriveSharedSecret({ privateKey: a, peerPublicKey: B });
    check('X25519 shared secret (RFC 7748)',
          bytesToHex(res.output) === expected,
          bytesToHex(res.output) !== expected
              ? `expected ${expected}\n      actual   ${bytesToHex(res.output)}` : '');
}

// -------------------------------------------------------------
console.log('\n=== ECDSA round trip (P-256 + SHA-256) ===');
{
    const kp = await cl.asymmetric.generateEcdsaKeypair({ curve: 'P-256' });
    const data = utf8ToBytes('cryptolab test');
    const sig = await cl.asymmetric.ecdsaSign({
        privateKey: kp.privateKey, curve: 'P-256', hash: 'SHA-256', data });
    const v = await cl.asymmetric.ecdsaVerify({
        publicKey: kp.publicKey, curve: 'P-256', hash: 'SHA-256',
        data, signature: sig.output });
    check('ECDSA P-256 sign+verify round trip', v.valid === true);
    // Tampered data should fail
    const bad = await cl.asymmetric.ecdsaVerify({
        publicKey: kp.publicKey, curve: 'P-256', hash: 'SHA-256',
        data: utf8ToBytes('tampered'), signature: sig.output });
    check('ECDSA P-256 rejects tampered data', bad.valid === false);
}

// -------------------------------------------------------------
console.log('\n=== RSA-OAEP round trip ===');
{
    const kp = await cl.asymmetric.generateRsaKeypair({ bits: 2048 });
    const data = utf8ToBytes('rsa-oaep round trip');
    const ct = await cl.asymmetric.rsaOaepEncrypt({
        publicKey: kp.publicKey, data });
    const pt = await cl.asymmetric.rsaOaepDecrypt({
        privateKey: kp.privateKey, data: ct.output });
    check('RSA-OAEP-2048 round trip',
          new TextDecoder().decode(pt.output) === 'rsa-oaep round trip');
}

console.log(`\n${pass} passed, ${fail} failed.`);
process.exit(fail === 0 ? 0 : 1);
