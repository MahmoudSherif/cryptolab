// ui/tabs/asymmetric.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    // Module-level keypair stash, so signing cards can read what was just
    // generated without forcing the user to copy/paste through the clipboard.
    const lastKeys = {};

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('Asymmetric',
            'Public-key cryptography: keypair generation, sign/verify, encrypt/decrypt, ' +
            'and key exchange. RSA and ECDSA use Web Crypto with SPKI/PKCS#8 DER key formats. ' +
            'Ed25519, X25519, and secp256k1 use noble-curves with raw 32-byte keys.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_rsaCard());
        cards.appendChild(_ecdsaCard());
        cards.appendChild(_ed25519Card());
        cards.appendChild(_x25519Card());
        cards.appendChild(_secp256k1Card());
        root.appendChild(cards);
        return root;
    }

    // ---------- RSA ----------
    function _rsaCard() {
        const c = ui.card({ num: '05.A', title: 'RSA' });

        const usage = ui.selectField({
            id: 'rsa-usage', label: 'Mode',
            options: [
                { value: 'oaep',  label: 'RSA-OAEP (encrypt/decrypt)' },
                { value: 'pss',   label: 'RSA-PSS (sign/verify)' },
                { value: 'pkcs1', label: 'RSASSA-PKCS1-v1_5 (legacy sign/verify)' },
            ],
            defaultValue: 'oaep',
        });
        const bits = ui.selectField({
            id: 'rsa-bits', label: 'Modulus',
            options: [
                { value: '2048', label: '2048 bits' },
                { value: '3072', label: '3072 bits' },
                { value: '4096', label: '4096 bits (slow)' },
                { value: '1024', label: '1024 bits (insecure)' },
            ],
            defaultValue: '2048',
        });
        const hashSel = ui.selectField({
            id: 'rsa-hash', label: 'Hash',
            options: ['SHA-256', 'SHA-384', 'SHA-512'],
            defaultValue: 'SHA-256',
        });

        c.body.appendChild(usage);
        c.body.appendChild(bits);
        c.body.appendChild(hashSel);

        // Public/private key fields
        const pubKey  = ui.byteField({ id: 'rsa-pub',  label: 'Public key (SPKI DER)',  defaultEncoding: 'base64', multiline: true });
        const privKey = ui.byteField({ id: 'rsa-priv', label: 'Private key (PKCS#8)',   defaultEncoding: 'base64', multiline: true });
        c.body.appendChild(pubKey);
        c.body.appendChild(privKey);

        // Generate keypair button
        const genRow = ui.el('div', { class: 'btn-row' });
        genRow.appendChild(ui.runButton({
            label: 'Generate keypair',
            onRun: async () => {
                const res = await cl.asymmetric.generateRsaKeypair({
                    bits: parseInt(bits.getValue()),
                    hash: hashSel.getValue(),
                    usage: usage.getValue(),
                });
                pubKey.setBytes(res.publicKey);
                privKey.setBytes(res.privateKey);
                lastKeys.rsa = res;
                _flashStatus(genRow, 'keypair generated');
            },
        }));
        c.body.appendChild(genRow);

        // Operation: encrypt/decrypt OR sign/verify, depending on usage.
        const op = ui.selectField({
            id: 'rsa-op', label: 'Operation',
            options: [
                { value: 'encrypt', label: 'Encrypt (with public key)' },
                { value: 'decrypt', label: 'Decrypt (with private key)' },
            ],
            defaultValue: 'encrypt',
        });
        c.body.appendChild(op);

        usage.select.addEventListener('change', () => {
            const u = usage.getValue();
            const opts = u === 'oaep'
                ? [{ value: 'encrypt', label: 'Encrypt (public key)' }, { value: 'decrypt', label: 'Decrypt (private key)' }]
                : [{ value: 'sign',    label: 'Sign (private key)' },   { value: 'verify',  label: 'Verify (public key)' }];
            // Rebuild select options
            op.select.innerHTML = '';
            for (const o of opts) {
                const e = document.createElement('option');
                e.value = o.value; e.textContent = o.label;
                op.select.appendChild(e);
            }
        });

        const message = ui.byteField({
            id: 'rsa-msg', label: 'Message / ciphertext',
            multiline: true, defaultEncoding: 'utf8',
        });
        const signatureField = ui.byteField({
            id: 'rsa-sig', label: 'Signature',
            multiline: true, defaultEncoding: 'hex',
            help: 'Required for verify only.',
        });
        c.body.appendChild(message);
        c.body.appendChild(signatureField);

        const output = ui.el('div');
        c.body.appendChild(output);

        const runRow = ui.el('div', { class: 'btn-row' });
        runRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const u = usage.getValue();
                    const o = op.getValue();
                    const h = hashSel.getValue();
                    const sec = ui.el('div', { class: 'output-section' });

                    if (u === 'oaep' && o === 'encrypt') {
                        const res = await cl.asymmetric.rsaOaepEncrypt({
                            publicKey: pubKey.getBytes(), hash: h, data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Ciphertext', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else if (u === 'oaep' && o === 'decrypt') {
                        const res = await cl.asymmetric.rsaOaepDecrypt({
                            privateKey: privKey.getBytes(), hash: h, data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Plaintext', value: res.output, encoding: 'utf8' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else if (u === 'pss' && o === 'sign') {
                        const res = await cl.asymmetric.rsaPssSign({
                            privateKey: privKey.getBytes(), hash: h, data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Signature', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else if (u === 'pss' && o === 'verify') {
                        const res = await cl.asymmetric.rsaPssVerify({
                            publicKey: pubKey.getBytes(), hash: h,
                            data: message.getBytes(), signature: signatureField.getBytes(),
                        });
                        sec.appendChild(ui.banner(res.valid ? 'ok' : 'error',
                            res.valid ? 'Signature is valid.' : 'Signature is INVALID.'));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else if (u === 'pkcs1' && o === 'sign') {
                        const res = await cl.asymmetric.rsaPkcs1Sign({
                            privateKey: privKey.getBytes(), hash: h, data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Signature', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else if (u === 'pkcs1' && o === 'verify') {
                        const res = await cl.asymmetric.rsaPkcs1Verify({
                            publicKey: pubKey.getBytes(), hash: h,
                            data: message.getBytes(), signature: signatureField.getBytes(),
                        });
                        sec.appendChild(ui.banner(res.valid ? 'ok' : 'error',
                            res.valid ? 'Signature is valid.' : 'Signature is INVALID.'));
                        sec.appendChild(ui.paramsTable(res.params));
                    }
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(runRow);
        return c;
    }

    // ---------- ECDSA ----------
    function _ecdsaCard() {
        const c = ui.card({ num: '05.B', title: 'ECDSA (NIST P-curves)' });

        const curve = ui.selectField({
            id: 'ec-curve', label: 'Curve',
            options: ['P-256', 'P-384', 'P-521'],
            defaultValue: 'P-256',
        });
        const hashSel = ui.selectField({
            id: 'ec-hash', label: 'Hash',
            options: ['SHA-256', 'SHA-384', 'SHA-512'],
            defaultValue: 'SHA-256',
        });
        c.body.appendChild(curve);
        c.body.appendChild(hashSel);

        const pubKey  = ui.byteField({ id: 'ec-pub',  label: 'Public key (SPKI)', multiline: true, defaultEncoding: 'base64' });
        const privKey = ui.byteField({ id: 'ec-priv', label: 'Private key (PKCS#8)', multiline: true, defaultEncoding: 'base64' });
        c.body.appendChild(pubKey);
        c.body.appendChild(privKey);

        const genRow = ui.el('div', { class: 'btn-row' });
        genRow.appendChild(ui.runButton({
            label: 'Generate keypair',
            onRun: async () => {
                const res = await cl.asymmetric.generateEcdsaKeypair({ curve: curve.getValue() });
                pubKey.setBytes(res.publicKey);
                privKey.setBytes(res.privateKey);
                lastKeys.ecdsa = res;
                _flashStatus(genRow, 'keypair generated');
            },
        }));
        c.body.appendChild(genRow);

        const op = ui.selectField({
            id: 'ec-op', label: 'Operation',
            options: [
                { value: 'sign',   label: 'Sign (private key)' },
                { value: 'verify', label: 'Verify (public key)' },
            ],
            defaultValue: 'sign',
        });
        const message = ui.byteField({ id: 'ec-msg', label: 'Message', multiline: true, defaultEncoding: 'utf8' });
        const signatureField = ui.byteField({ id: 'ec-sig', label: 'Signature', multiline: true, defaultEncoding: 'hex',
            help: 'IEEE P1363 format (r||s, raw concatenated).' });
        c.body.appendChild(op);
        c.body.appendChild(message);
        c.body.appendChild(signatureField);

        const output = ui.el('div');
        c.body.appendChild(output);

        const runRow = ui.el('div', { class: 'btn-row' });
        runRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const sec = ui.el('div', { class: 'output-section' });
                    if (op.getValue() === 'sign') {
                        const res = await cl.asymmetric.ecdsaSign({
                            privateKey: privKey.getBytes(), curve: curve.getValue(),
                            hash: hashSel.getValue(), data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Signature (r || s)', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else {
                        const res = await cl.asymmetric.ecdsaVerify({
                            publicKey: pubKey.getBytes(), curve: curve.getValue(),
                            hash: hashSel.getValue(), data: message.getBytes(),
                            signature: signatureField.getBytes(),
                        });
                        sec.appendChild(ui.banner(res.valid ? 'ok' : 'error',
                            res.valid ? 'Signature is valid.' : 'Signature is INVALID.'));
                        sec.appendChild(ui.paramsTable(res.params));
                    }
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(runRow);
        return c;
    }

    // ---------- Ed25519 ----------
    function _ed25519Card() {
        const c = ui.card({ num: '05.C', title: 'Ed25519 (RFC 8032)' });

        const pubKey  = ui.byteField({ id: 'ed-pub',  label: 'Public key',  requireBytes: 32, defaultEncoding: 'hex' });
        const privKey = ui.byteField({ id: 'ed-priv', label: 'Private key', requireBytes: 32, defaultEncoding: 'hex',
            help: 'The 32-byte seed (RFC 8032 calls this k).' });
        c.body.appendChild(pubKey);
        c.body.appendChild(privKey);

        const genRow = ui.el('div', { class: 'btn-row' });
        genRow.appendChild(ui.runButton({
            label: 'Generate keypair',
            onRun: () => {
                const res = cl.asymmetric.generateEd25519Keypair();
                pubKey.setBytes(res.publicKey);
                privKey.setBytes(res.privateKey);
                lastKeys.ed25519 = res;
                _flashStatus(genRow, 'keypair generated');
            },
        }));
        c.body.appendChild(genRow);

        const op = ui.selectField({
            id: 'ed-op', label: 'Operation',
            options: [{ value: 'sign', label: 'Sign' }, { value: 'verify', label: 'Verify' }],
            defaultValue: 'sign',
        });
        const message = ui.byteField({ id: 'ed-msg', label: 'Message', multiline: true, defaultEncoding: 'utf8' });
        const signatureField = ui.byteField({ id: 'ed-sig', label: 'Signature', multiline: true,
            requireBytes: 64, defaultEncoding: 'hex' });
        c.body.appendChild(op);
        c.body.appendChild(message);
        c.body.appendChild(signatureField);

        const output = ui.el('div');
        c.body.appendChild(output);

        const runRow = ui.el('div', { class: 'btn-row' });
        runRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const sec = ui.el('div', { class: 'output-section' });
                    if (op.getValue() === 'sign') {
                        const res = cl.asymmetric.ed25519Sign({
                            privateKey: privKey.getBytes(), data: message.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Signature (R || S)', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else {
                        const res = cl.asymmetric.ed25519Verify({
                            publicKey: pubKey.getBytes(), data: message.getBytes(),
                            signature: signatureField.getBytes(),
                        });
                        sec.appendChild(ui.banner(res.valid ? 'ok' : 'error',
                            res.valid ? 'Signature is valid.' : 'Signature is INVALID.'));
                        sec.appendChild(ui.paramsTable(res.params));
                    }
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(runRow);
        return c;
    }

    // ---------- X25519 ----------
    function _x25519Card() {
        const c = ui.card({ num: '05.D', title: 'X25519 (RFC 7748 key exchange)' });

        const pubKey  = ui.byteField({ id: 'x-pub',  label: 'Your public key',  requireBytes: 32, defaultEncoding: 'hex' });
        const privKey = ui.byteField({ id: 'x-priv', label: 'Your private key', requireBytes: 32, defaultEncoding: 'hex' });
        c.body.appendChild(pubKey);
        c.body.appendChild(privKey);

        const genRow = ui.el('div', { class: 'btn-row' });
        genRow.appendChild(ui.runButton({
            label: 'Generate keypair',
            onRun: () => {
                const res = cl.asymmetric.generateX25519Keypair();
                pubKey.setBytes(res.publicKey);
                privKey.setBytes(res.privateKey);
                _flashStatus(genRow, 'keypair generated');
            },
        }));
        c.body.appendChild(genRow);

        const peerPub = ui.byteField({
            id: 'x-peer', label: "Peer's public key",
            requireBytes: 32, defaultEncoding: 'hex',
        });
        c.body.appendChild(peerPub);

        const output = ui.el('div');
        c.body.appendChild(output);

        const runRow = ui.el('div', { class: 'btn-row' });
        runRow.appendChild(ui.runButton({
            label: 'Derive shared secret',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const res = cl.asymmetric.x25519DeriveSharedSecret({
                        privateKey: privKey.getBytes(),
                        peerPublicKey: peerPub.getBytes(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: 'Shared secret (32 bytes)',
                        value: res.output, encoding: 'hex',
                    }));
                    sec.appendChild(ui.banner('warning',
                        'Never use this raw secret as a key. Run it through HKDF (KDF tab) ' +
                        'with appropriate salt/info to derive your actual session key.'));
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(runRow);
        return c;
    }

    // ---------- secp256k1 ----------
    function _secp256k1Card() {
        const c = ui.card({ num: '05.E', title: 'secp256k1 (Bitcoin / Ethereum)' });

        const pubKey  = ui.byteField({ id: 'sk-pub',  label: 'Public key (compressed)',
            requireBytes: 33, defaultEncoding: 'hex', help: '33 bytes: 0x02 or 0x03 prefix + 32-byte X coord.' });
        const privKey = ui.byteField({ id: 'sk-priv', label: 'Private key', requireBytes: 32, defaultEncoding: 'hex' });
        c.body.appendChild(pubKey);
        c.body.appendChild(privKey);

        const genRow = ui.el('div', { class: 'btn-row' });
        genRow.appendChild(ui.runButton({
            label: 'Generate keypair',
            onRun: () => {
                const res = cl.asymmetric.generateSecp256k1Keypair();
                pubKey.setBytes(res.publicKey);
                privKey.setBytes(res.privateKey);
                _flashStatus(genRow, 'keypair generated');
            },
        }));
        c.body.appendChild(genRow);

        const op = ui.selectField({
            id: 'sk-op', label: 'Operation',
            options: [{ value: 'sign', label: 'Sign' }, { value: 'verify', label: 'Verify' }],
            defaultValue: 'sign',
        });
        const msgHash = ui.byteField({
            id: 'sk-msghash', label: 'Message hash',
            requireBytes: 32, defaultEncoding: 'hex',
            help: 'secp256k1 signs a 32-byte hash, not raw messages. Hash with SHA-256 (Bitcoin) or Keccak-256 (Ethereum) first.',
        });
        const signatureField = ui.byteField({
            id: 'sk-sig', label: 'Signature (compact r||s)',
            requireBytes: 64, defaultEncoding: 'hex',
        });
        c.body.appendChild(op);
        c.body.appendChild(msgHash);
        c.body.appendChild(signatureField);

        const output = ui.el('div');
        c.body.appendChild(output);

        const runRow = ui.el('div', { class: 'btn-row' });
        runRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const sec = ui.el('div', { class: 'output-section' });
                    if (op.getValue() === 'sign') {
                        const res = cl.asymmetric.secp256k1Sign({
                            privateKey: privKey.getBytes(),
                            msgHash: msgHash.getBytes(),
                        });
                        sec.appendChild(ui.outputBlock({ label: 'Signature (r || s)', value: res.output, encoding: 'hex' }));
                        sec.appendChild(ui.paramsTable(res.params));
                    } else {
                        const res = cl.asymmetric.secp256k1Verify({
                            publicKey: pubKey.getBytes(),
                            msgHash: msgHash.getBytes(),
                            signature: signatureField.getBytes(),
                        });
                        sec.appendChild(ui.banner(res.valid ? 'ok' : 'error',
                            res.valid ? 'Signature is valid.' : 'Signature is INVALID.'));
                        sec.appendChild(ui.paramsTable(res.params));
                    }
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(runRow);
        return c;
    }

    // ---------- helpers ----------
    function _flashStatus(parent, text) {
        let badge = parent.querySelector('.flash-badge');
        if (!badge) {
            badge = ui.el('span', { class: 'flash-badge phosphor', style: 'font-size:11px; letter-spacing:0.06em;' });
            parent.appendChild(badge);
        }
        badge.textContent = '✓ ' + text;
        clearTimeout(badge._t);
        badge._t = setTimeout(() => badge.textContent = '', 2000);
    }

    function _head(title, desc) {
        const head = ui.el('div', { class: 'panel-head' });
        const h = ui.el('h2'); h.textContent = title; head.appendChild(h);
        const p = ui.el('p'); p.textContent = desc; head.appendChild(p);
        return head;
    }

    global.cryptolab.tabs = global.cryptolab.tabs || {};
    global.cryptolab.tabs.asymmetric = { build };

})(typeof window !== 'undefined' ? window : globalThis);
