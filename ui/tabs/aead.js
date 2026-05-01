// ui/tabs/aead.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    const ALGORITHMS = [
        { value: 'aes-gcm',     label: 'AES-GCM',           keyBytes: [16, 24, 32], nonceBytes: [12], tagBits: [128, 120, 112, 104, 96, 64, 32] },
        { value: 'chacha20p1305',   label: 'ChaCha20-Poly1305', keyBytes: [32], nonceBytes: [12] },
        { value: 'xchacha20p1305', label: 'XChaCha20-Poly1305', keyBytes: [32], nonceBytes: [24] },
    ];

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('AEAD',
            'Authenticated encryption with associated data. Encrypted output is ' +
            'ciphertext || tag concatenated. Decryption verifies the tag before ' +
            'returning plaintext — wrong key, nonce, AAD, or tampered ciphertext ' +
            'all produce an authentication failure.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_aeadCard());
        root.appendChild(cards);
        return root;
    }

    function _aeadCard() {
        const c = ui.card({ num: '02.A', title: 'AEAD encrypt / decrypt' });

        const algorithm = ui.selectField({
            id: 'aead-alg', label: 'Algorithm',
            options: ALGORITHMS.map(a => ({ value: a.value, label: a.label })),
            defaultValue: 'aes-gcm',
            onChange: (v) => updateLimits(v),
        });
        const mode = ui.selectField({
            id: 'aead-mode', label: 'Mode',
            options: [{ value: 'encrypt', label: 'Encrypt' }, { value: 'decrypt', label: 'Decrypt' }],
            defaultValue: 'encrypt',
        });

        const key = ui.byteField({
            id: 'aead-key', label: 'Key', required: true,
            defaultEncoding: 'hex',
        });
        const genKey = ui.el('button', { class: 'mini-btn', type: 'button' });
        genKey.textContent = 'random key';
        genKey.addEventListener('click', () => {
            const sel = ALGORITHMS.find(a => a.value === algorithm.getValue());
            key.setBytes(enc.randomBytes(sel.keyBytes[sel.keyBytes.length - 1])); // largest
        });
        key.metaActions.appendChild(genKey);

        const nonce = ui.byteField({
            id: 'aead-nonce', label: 'Nonce / IV', required: true,
            defaultEncoding: 'hex',
        });
        const genNonce = ui.el('button', { class: 'mini-btn', type: 'button' });
        genNonce.textContent = 'random nonce';
        genNonce.addEventListener('click', () => {
            const sel = ALGORITHMS.find(a => a.value === algorithm.getValue());
            nonce.setBytes(enc.randomBytes(sel.nonceBytes[0]));
        });
        nonce.metaActions.appendChild(genNonce);

        const aad = ui.byteField({
            id: 'aead-aad', label: 'AAD',
            help: 'Associated data — authenticated but not encrypted. Optional.',
            defaultEncoding: 'utf8',
        });

        const data = ui.byteField({
            id: 'aead-data', label: 'Plaintext / ciphertext',
            multiline: true, required: true,
            defaultEncoding: 'utf8',
        });

        c.body.appendChild(algorithm);
        c.body.appendChild(mode);
        c.body.appendChild(key);
        c.body.appendChild(nonce);
        c.body.appendChild(aad);
        c.body.appendChild(data);

        const output = ui.el('div');
        c.body.appendChild(output);

        function updateLimits(algoVal) {
            const sel = ALGORITHMS.find(a => a.value === algoVal);
            // Update placeholders / required key sizes.
            key.input.placeholder = `key: ${sel.keyBytes.join(' or ')} bytes`;
            nonce.input.placeholder = `nonce: ${sel.nonceBytes.join(' or ')} bytes`;
        }
        updateLimits(algorithm.getValue());

        // Update encoding on the data field based on mode.
        mode.select.addEventListener('change', () => {
            // In decrypt mode, data is hex-ish ciphertext; switch encoding hint.
            if (mode.getValue() === 'decrypt') {
                data.setEncoding('hex');
            } else {
                data.setEncoding('utf8');
            }
        });

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const op = mode.getValue();
                    const algoVal = algorithm.getValue();
                    const aadBytes = aad.getBytes();
                    const params = {
                        key: key.getBytes(),
                        data: data.getBytes(),
                        aad: aadBytes.length ? aadBytes : undefined,
                    };
                    let res;
                    if (algoVal === 'aes-gcm') {
                        params.iv = nonce.getBytes();
                        res = await cl.aead.aesGcm(op, params);
                    } else if (algoVal === 'chacha20p1305') {
                        params.nonce = nonce.getBytes();
                        res = cl.aead.chacha20Poly1305(op, params);
                    } else if (algoVal === 'xchacha20p1305') {
                        params.nonce = nonce.getBytes();
                        res = cl.aead.xchacha20Poly1305(op, params);
                    }
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: op === 'encrypt' ? 'Ciphertext + tag' : 'Plaintext',
                        value: res.output, encoding: 'hex',
                        copyAs: op === 'decrypt' ? ['utf8', 'hex'] : ['hex', 'base64'],
                    }));
                    if (op === 'encrypt') {
                        // Show the tag separated for clarity.
                        const tagBytes = res.params.tagBits / 8;
                        const ct = res.output.subarray(0, res.output.length - tagBytes);
                        const tag = res.output.subarray(res.output.length - tagBytes);
                        sec.appendChild(ui.outputBlock({
                            label: `Tag (${res.params.tagBits} bits)`,
                            value: tag, encoding: 'hex',
                        }));
                        sec.appendChild(ui.outputBlock({
                            label: `Ciphertext (without tag)`,
                            value: ct, encoding: 'hex',
                        }));
                    }
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) {
                    output.appendChild(ui.banner('error', e.message));
                }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    function _head(title, desc) {
        const head = ui.el('div', { class: 'panel-head' });
        const h = ui.el('h2'); h.textContent = title; head.appendChild(h);
        const p = ui.el('p'); p.textContent = desc; head.appendChild(p);
        return head;
    }

    global.cryptolab.tabs = global.cryptolab.tabs || {};
    global.cryptolab.tabs.aead = { build };

})(typeof window !== 'undefined' ? window : globalThis);
