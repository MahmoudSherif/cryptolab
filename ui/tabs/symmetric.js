// ui/tabs/symmetric.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('Symmetric (non-AEAD)',
            'Block ciphers and stream ciphers without authentication. ' +
            'WARNING: prefer AEAD (next tab) for any new design — ' +
            'unauthenticated modes are vulnerable to bit-flipping and padding-oracle attacks.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_aesCard());
        cards.appendChild(_chachaCard());
        root.appendChild(cards);
        return root;
    }

    function _aesCard() {
        const c = ui.card({ num: '01.A', title: 'AES (CBC / CTR / ECB)' });

        const mode = ui.selectField({
            id: 'aes-mode', label: 'Mode',
            options: [
                { value: 'cbc', label: 'CBC (block, requires IV)' },
                { value: 'ctr', label: 'CTR (stream-like, requires counter)' },
                { value: 'ecb', label: 'ECB (insecure — educational only)' },
            ],
            defaultValue: 'cbc',
        });
        const op = ui.selectField({
            id: 'aes-op', label: 'Operation',
            options: [{ value: 'encrypt', label: 'Encrypt' }, { value: 'decrypt', label: 'Decrypt' }],
            defaultValue: 'encrypt',
        });
        const key = ui.byteField({
            id: 'aes-key', label: 'Key', required: true,
            help: 'AES-128: 16 bytes · AES-192: 24 · AES-256: 32',
            defaultEncoding: 'hex',
        });
        const genKey128 = ui.el('button', { class: 'mini-btn', type: 'button' });
        genKey128.textContent = 'AES-128';
        genKey128.addEventListener('click', () => key.setBytes(enc.randomBytes(16)));
        const genKey256 = ui.el('button', { class: 'mini-btn', type: 'button' });
        genKey256.textContent = 'AES-256';
        genKey256.addEventListener('click', () => key.setBytes(enc.randomBytes(32)));
        key.metaActions.appendChild(genKey128);
        key.metaActions.appendChild(genKey256);

        const ivLabel = ui.byteField({
            id: 'aes-iv', label: 'IV / counter',
            requireBytes: 16,
            help: 'CBC: 16-byte IV. CTR: full 16-byte counter block (8 nonce + 8 counter typical).',
            defaultEncoding: 'hex',
        });
        const genIv = ui.el('button', { class: 'mini-btn', type: 'button' });
        genIv.textContent = 'random 16 bytes';
        genIv.addEventListener('click', () => ivLabel.setBytes(enc.randomBytes(16)));
        ivLabel.metaActions.appendChild(genIv);

        const padding = ui.selectField({
            id: 'aes-padding', label: 'Padding',
            options: [{ value: 'pkcs7', label: 'PKCS#7' }, { value: 'none', label: 'None' }],
            defaultValue: 'pkcs7',
            help: 'PKCS#7 is standard. "None" requires data length to be a multiple of 16 (CBC/ECB only).',
        });
        const data = ui.byteField({
            id: 'aes-data', label: 'Data', multiline: true, required: true,
            defaultEncoding: 'utf8',
        });

        c.body.appendChild(mode);
        c.body.appendChild(op);
        c.body.appendChild(key);
        c.body.appendChild(ivLabel);
        c.body.appendChild(padding);
        c.body.appendChild(data);

        // Show/hide IV row based on mode (ECB has no IV).
        mode.select.addEventListener('change', () => {
            const m = mode.getValue();
            ivLabel.style.display = m === 'ecb' ? 'none' : '';
            padding.style.display = m === 'ctr' ? 'none' : '';
            if (m === 'ecb') {
                // Show ECB warning
                if (!c.body.querySelector('.ecb-warn')) {
                    const w = ui.banner('warning',
                        'ECB mode reveals patterns in your plaintext. The classic "ECB penguin" demonstrates this. Never use in production.');
                    w.classList.add('ecb-warn');
                    c.body.insertBefore(w, mode.nextSibling);
                }
            } else {
                const w = c.body.querySelector('.ecb-warn');
                if (w) w.remove();
            }
        });

        op.select.addEventListener('change', () => {
            data.setEncoding(op.getValue() === 'decrypt' ? 'hex' : 'utf8');
        });

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Run',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const m = mode.getValue();
                    const params = {
                        key: key.getBytes(),
                        data: data.getBytes(),
                    };
                    let res;
                    if (m === 'cbc') {
                        params.iv = ivLabel.getBytes();
                        params.padding = padding.getValue();
                        res = await cl.symmetric.aesCbc(op.getValue(), params);
                    } else if (m === 'ctr') {
                        params.nonce = ivLabel.getBytes();
                        res = await cl.symmetric.aesCtr(op.getValue(), params);
                    } else {
                        params.padding = padding.getValue();
                        res = await cl.symmetric.aesEcb(op.getValue(), params);
                    }
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: op.getValue() === 'encrypt' ? 'Ciphertext' : 'Plaintext',
                        value: res.output,
                        encoding: 'hex',
                        copyAs: op.getValue() === 'decrypt' ? ['utf8', 'hex'] : ['hex', 'base64'],
                    }));
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

    function _chachaCard() {
        const c = ui.card({ num: '01.B', title: 'ChaCha20 (raw stream)' });
        const note = ui.banner('warning',
            'Raw ChaCha20 has no authentication. Use ChaCha20-Poly1305 (in the AEAD tab) ' +
            'for any real protocol — this card is for test vectors and interop debugging only.');
        c.body.appendChild(note);

        const key = ui.byteField({
            id: 'cc-key', label: 'Key', required: true, requireBytes: 32,
            defaultEncoding: 'hex',
        });
        const genKey = ui.el('button', { class: 'mini-btn', type: 'button' });
        genKey.textContent = 'random key';
        genKey.addEventListener('click', () => key.setBytes(enc.randomBytes(32)));
        key.metaActions.appendChild(genKey);

        const nonce = ui.byteField({
            id: 'cc-nonce', label: 'Nonce', required: true, requireBytes: 12,
            help: 'IETF ChaCha20: 12 bytes',
            defaultEncoding: 'hex',
        });
        const genNonce = ui.el('button', { class: 'mini-btn', type: 'button' });
        genNonce.textContent = 'random nonce';
        genNonce.addEventListener('click', () => nonce.setBytes(enc.randomBytes(12)));
        nonce.metaActions.appendChild(genNonce);

        const counter = ui.numberField({
            id: 'cc-ctr', label: 'Initial counter', defaultValue: 0, min: 0, max: 0xFFFFFFFF,
            help: 'RFC 8439 starts at 0 for the first encrypted block.',
        });
        const data = ui.byteField({
            id: 'cc-data', label: 'Data', multiline: true, required: true,
            defaultEncoding: 'utf8',
        });

        c.body.appendChild(key);
        c.body.appendChild(nonce);
        c.body.appendChild(counter);
        c.body.appendChild(data);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'XOR with keystream',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const res = cl.symmetric.chacha20('encrypt', {
                        key: key.getBytes(),
                        nonce: nonce.getBytes(),
                        data: data.getBytes(),
                        counter: counter.getValue(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: 'Output',
                        value: res.output, encoding: 'hex',
                    }));
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
    global.cryptolab.tabs.symmetric = { build };

})(typeof window !== 'undefined' ? window : globalThis);
