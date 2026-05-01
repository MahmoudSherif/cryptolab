// ui/tabs/kdf.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('Key derivation',
            'Derive cryptographic keys from passwords (PBKDF2, scrypt, Argon2) or from existing key material (HKDF). ' +
            'WARNING: scrypt and Argon2 are tunable — strong parameters take seconds in-browser by design.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_pbkdf2Card());
        cards.appendChild(_hkdfCard());
        cards.appendChild(_scryptCard());
        cards.appendChild(_argon2Card());
        root.appendChild(cards);
        return root;
    }

    function _pbkdf2Card() {
        const c = ui.card({ num: '04.A', title: 'PBKDF2' });
        const password = ui.byteField({ id: 'pb-pw', label: 'Password', required: true, defaultEncoding: 'utf8' });
        const salt = ui.byteField({ id: 'pb-salt', label: 'Salt', required: true, minBytes: 8, defaultEncoding: 'hex' });
        const genSalt = ui.el('button', { class: 'mini-btn', type: 'button' });
        genSalt.textContent = 'random 16 bytes';
        genSalt.addEventListener('click', () => salt.setBytes(enc.randomBytes(16)));
        salt.metaActions.appendChild(genSalt);

        const hashSel = ui.selectField({
            id: 'pb-hash', label: 'Hash',
            options: ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'],
            defaultValue: 'SHA-256',
        });
        const iterations = ui.numberField({
            id: 'pb-iter', label: 'Iterations', defaultValue: 600000, min: 1,
            help: 'OWASP-2023: 600k for SHA-256. Use much higher for offline storage.',
        });
        const dkLen = ui.numberField({ id: 'pb-len', label: 'dkLen (bytes)', defaultValue: 32, min: 1, max: 1024 });

        c.body.appendChild(password);
        c.body.appendChild(salt);
        c.body.appendChild(hashSel);
        c.body.appendChild(iterations);
        c.body.appendChild(dkLen);

        const output = ui.el('div');
        c.body.appendChild(output);
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Derive',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const t0 = performance.now();
                    const res = await cl.kdf.pbkdf2({
                        password: password.getBytes(),
                        salt: salt.getBytes(),
                        iterations: iterations.getValue(),
                        hash: hashSel.getValue(),
                        dkLen: dkLen.getValue(),
                    });
                    const elapsed = Math.round(performance.now() - t0);
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Derived key', value: res.output, encoding: 'hex' }));
                    res.params.elapsedMs = elapsed;
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    function _hkdfCard() {
        const c = ui.card({ num: '04.B', title: 'HKDF (RFC 5869)' });
        const ikm  = ui.byteField({ id: 'hk-ikm',  label: 'IKM', required: true, defaultEncoding: 'hex',
            help: 'Input key material — typically a shared secret from a key exchange.' });
        const salt = ui.byteField({ id: 'hk-salt', label: 'Salt', defaultEncoding: 'hex',
            help: 'Optional. Empty salt is allowed (RFC 5869).' });
        const info = ui.byteField({ id: 'hk-info', label: 'Info', defaultEncoding: 'utf8',
            help: 'Optional context binding (e.g. "myapp v1 session-key").' });
        const hashSel = ui.selectField({
            id: 'hk-hash', label: 'Hash',
            options: ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512'],
            defaultValue: 'SHA-256',
        });
        const dkLen = ui.numberField({ id: 'hk-len', label: 'dkLen (bytes)', defaultValue: 32, min: 1, max: 8160 });

        c.body.appendChild(ikm);
        c.body.appendChild(salt);
        c.body.appendChild(info);
        c.body.appendChild(hashSel);
        c.body.appendChild(dkLen);

        const output = ui.el('div');
        c.body.appendChild(output);
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Derive',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const res = cl.kdf.hkdf({
                        ikm: ikm.getBytes(),
                        salt: salt.getBytes(),
                        info: info.getBytes(),
                        hash: hashSel.getValue(),
                        dkLen: dkLen.getValue(),
                    });
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Derived key', value: res.output, encoding: 'hex' }));
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    function _scryptCard() {
        const c = ui.card({ num: '04.C', title: 'scrypt (RFC 7914)' });
        const password = ui.byteField({ id: 'sc-pw',   label: 'Password', required: true, defaultEncoding: 'utf8' });
        const salt     = ui.byteField({ id: 'sc-salt', label: 'Salt',     required: true, defaultEncoding: 'hex' });
        const N = ui.numberField({ id: 'sc-N', label: 'N (cost)', defaultValue: 16384, min: 2,
            help: 'Must be a power of 2. Memory ≈ 128·N·r bytes. N=2¹⁷ ≈ 128 MiB.' });
        const r = ui.numberField({ id: 'sc-r', label: 'r (block size)', defaultValue: 8, min: 1 });
        const p = ui.numberField({ id: 'sc-p', label: 'p (parallel)',   defaultValue: 1, min: 1 });
        const dkLen = ui.numberField({ id: 'sc-len', label: 'dkLen (bytes)', defaultValue: 32, min: 1 });

        c.body.appendChild(password);
        c.body.appendChild(salt);
        c.body.appendChild(N);
        c.body.appendChild(r);
        c.body.appendChild(p);
        c.body.appendChild(dkLen);

        const output = ui.el('div');
        c.body.appendChild(output);
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Derive (slow)',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const t0 = performance.now();
                    const res = await cl.kdf.scrypt({
                        password: password.getBytes(),
                        salt: salt.getBytes(),
                        N: N.getValue(), r: r.getValue(), p: p.getValue(),
                        dkLen: dkLen.getValue(),
                    });
                    const elapsed = Math.round(performance.now() - t0);
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Derived key', value: res.output, encoding: 'hex' }));
                    res.params.elapsedMs = elapsed;
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    function _argon2Card() {
        const c = ui.card({ num: '04.D', title: 'Argon2 (RFC 9106)' });
        const password = ui.byteField({ id: 'ar-pw',   label: 'Password', required: true, defaultEncoding: 'utf8' });
        const salt     = ui.byteField({ id: 'ar-salt', label: 'Salt',     required: true, minBytes: 8, defaultEncoding: 'hex' });
        const variant = ui.selectField({
            id: 'ar-var', label: 'Variant',
            options: [{value:'argon2id',label:'Argon2id (recommended)'},
                      {value:'argon2i', label:'Argon2i'},
                      {value:'argon2d', label:'Argon2d'}],
            defaultValue: 'argon2id',
        });
        const t = ui.numberField({ id: 'ar-t', label: 't (passes)',     defaultValue: 3, min: 1 });
        const m = ui.numberField({ id: 'ar-m', label: 'm (KiB)',        defaultValue: 65536, min: 8,
            help: '65536 KiB = 64 MiB. RFC 9106 recommends ≥ 64 MiB for password hashing.' });
        const p = ui.numberField({ id: 'ar-p', label: 'p (parallelism)', defaultValue: 1, min: 1 });
        const dkLen = ui.numberField({ id: 'ar-len', label: 'dkLen (bytes)', defaultValue: 32, min: 4 });

        c.body.appendChild(password);
        c.body.appendChild(salt);
        c.body.appendChild(variant);
        c.body.appendChild(t);
        c.body.appendChild(m);
        c.body.appendChild(p);
        c.body.appendChild(dkLen);

        const output = ui.el('div');
        c.body.appendChild(output);
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Derive (slow)',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const t0 = performance.now();
                    // yield to UI
                    await new Promise(r => setTimeout(r, 0));
                    const res = cl.kdf.argon2({
                        password: password.getBytes(),
                        salt: salt.getBytes(),
                        variant: variant.getValue(),
                        t: t.getValue(), m: m.getValue(), p: p.getValue(),
                        dkLen: dkLen.getValue(),
                    });
                    const elapsed = Math.round(performance.now() - t0);
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Derived key', value: res.output, encoding: 'hex' }));
                    res.params.elapsedMs = elapsed;
                    sec.appendChild(ui.paramsTable(res.params));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
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
    global.cryptolab.tabs.kdf = { build };

})(typeof window !== 'undefined' ? window : globalThis);
