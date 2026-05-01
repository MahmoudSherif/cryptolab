// ui/tabs/hash.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('Hash & MAC',
            'One-shot hashing, HMAC, and KMAC across SHA-1/2/3, BLAKE2/3, Keccak. ' +
            'Web Crypto is used where supported (SHA-1/256/384/512); SHA-3 and BLAKE come from noble-hashes.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_hashCard());
        cards.appendChild(_hmacCard());
        cards.appendChild(_kmacCard());
        root.appendChild(cards);
        return root;
    }

    function _hashCard() {
        const c = ui.card({ num: '03.A', title: 'HASH' });

        const algorithm = ui.selectField({
            id: 'hash-alg', label: 'Algorithm',
            options: cl.hash.HASH_ALGORITHMS,
            defaultValue: 'SHA-256',
        });
        const data = ui.byteField({
            id: 'hash-data', label: 'Input', multiline: true,
            placeholder: 'Bytes to hash. Try "abc" in UTF-8.',
            defaultEncoding: 'utf8',
        });
        c.body.appendChild(algorithm);
        c.body.appendChild(data);

        const output = ui.el('div');
        c.body.appendChild(output);

        const run = ui.runButton({
            label: 'Hash',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const res = await cl.hash.hash({
                        algorithm: algorithm.getValue(),
                        data: data.getBytes(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: 'Digest', value: res.output, encoding: 'hex',
                    }));
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) {
                    output.appendChild(ui.banner('error', e.message));
                }
            },
        });
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(run);
        c.body.appendChild(btnRow);
        return c;
    }

    function _hmacCard() {
        const c = ui.card({ num: '03.B', title: 'HMAC' });

        const algorithm = ui.selectField({
            id: 'hmac-alg', label: 'Hash',
            options: cl.hash.HASH_ALGORITHMS.filter(a => !a.includes('BLAKE')),
            defaultValue: 'SHA-256',
        });
        const key = ui.byteField({
            id: 'hmac-key', label: 'Key', required: true,
            placeholder: '32 bytes recommended for HMAC-SHA-256',
            defaultEncoding: 'hex',
        });
        const data = ui.byteField({
            id: 'hmac-data', label: 'Message', multiline: true,
            placeholder: 'Message to authenticate.',
            defaultEncoding: 'utf8',
        });
        c.body.appendChild(algorithm);
        c.body.appendChild(key);
        c.body.appendChild(data);

        // Add a "generate key" mini button
        const genKeyBtn = ui.el('button', { class: 'mini-btn', type: 'button' });
        genKeyBtn.textContent = 'random 32-byte key';
        genKeyBtn.addEventListener('click', () => {
            key.setBytes(enc.randomBytes(32));
        });
        key.metaActions.appendChild(genKeyBtn);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Sign',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const res = await cl.hash.hmac({
                        algorithm: algorithm.getValue(),
                        key: key.getBytes(),
                        data: data.getBytes(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: 'Tag', value: res.output, encoding: 'hex',
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

    function _kmacCard() {
        const c = ui.card({ num: '03.C', title: 'KMAC (NIST SP 800-185)' });

        const variant = ui.selectField({
            id: 'kmac-variant', label: 'Variant',
            options: [{ value: '128', label: 'KMAC-128' }, { value: '256', label: 'KMAC-256' }],
            defaultValue: '128',
        });
        const key = ui.byteField({
            id: 'kmac-key', label: 'Key', required: true,
            defaultEncoding: 'hex',
        });
        const data = ui.byteField({
            id: 'kmac-data', label: 'Message', multiline: true,
            defaultEncoding: 'utf8',
        });
        const customization = ui.byteField({
            id: 'kmac-cust', label: 'Customization',
            help: 'Optional domain separation string (S parameter).',
            defaultEncoding: 'utf8',
        });
        const outputBytes = ui.numberField({
            id: 'kmac-out', label: 'Output bytes', defaultValue: 32, min: 1, max: 256,
        });

        c.body.appendChild(variant);
        c.body.appendChild(key);
        c.body.appendChild(data);
        c.body.appendChild(customization);
        c.body.appendChild(outputBytes);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Compute',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const cust = customization.getBytes();
                    const res = cl.hash.kmac({
                        variant: parseInt(variant.getValue()),
                        key: key.getBytes(),
                        data: data.getBytes(),
                        customization: cust.length ? cust : undefined,
                        outputBytes: outputBytes.getValue(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({
                        label: 'Output', value: res.output, encoding: 'hex',
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
        const h = ui.el('h2');
        h.textContent = title;
        head.appendChild(h);
        const p = ui.el('p');
        p.textContent = desc;
        head.appendChild(p);
        return head;
    }

    global.cryptolab.tabs = global.cryptolab.tabs || {};
    global.cryptolab.tabs.hash = { build };

})(typeof window !== 'undefined' ? window : globalThis);
