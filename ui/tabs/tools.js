// ui/tabs/tools.js
(function (global) {
    'use strict';
    const cl = global.cryptolab;
    const ui = cl.ui;
    const enc = cl.encoding;

    function build() {
        const root = ui.el('div');
        root.appendChild(_head('Tools',
            'Utility operations for encoding, randomness, tampering, and comparison. ' +
            'These are the small primitives you reach for constantly when debugging crypto.'));

        const cards = ui.el('div', { class: 'cards' });
        cards.appendChild(_encodingCard());
        cards.appendChild(_randomCard());
        cards.appendChild(_tamperCard());
        cards.appendChild(_compareCard());
        root.appendChild(cards);
        return root;
    }

    // ---------- Encoding converter ----------
    function _encodingCard() {
        const c = ui.card({ num: '06.A', title: 'Encoding converter' });

        const input = ui.byteField({
            id: 'conv-in', label: 'Input', multiline: true,
            placeholder: 'Paste anything — hex, base64, or text. Encoding auto-detects.',
            defaultEncoding: 'utf8',
        });
        c.body.appendChild(input);

        const output = ui.el('div');
        c.body.appendChild(output);

        function refresh() {
            output.innerHTML = '';
            try {
                const bytes = input.getBytes();
                const sec = ui.el('div', { class: 'output-section' });
                sec.appendChild(ui.outputBlock({ label: 'Hex',         value: bytes, encoding: 'hex' }));
                sec.appendChild(ui.outputBlock({ label: 'Hex (grouped, 4-byte words)',
                    value: enc.bytesToHexPretty(bytes, 4),
                    copyAs: ['hex'] }));
                sec.appendChild(ui.outputBlock({ label: 'Base64',      value: bytes, encoding: 'base64' }));
                sec.appendChild(ui.outputBlock({ label: 'Base64URL',   value: bytes, encoding: 'base64url' }));
                try {
                    const utf8 = enc.bytesToUtf8(bytes, { strict: true });
                    sec.appendChild(ui.outputBlock({ label: 'UTF-8',   value: utf8, encoding: 'utf8' }));
                } catch (e) {
                    sec.appendChild(ui.outputBlock({
                        label: 'UTF-8 (invalid byte sequence — showing replacement)',
                        value: enc.bytesToUtf8(bytes), encoding: 'utf8',
                    }));
                }
                sec.appendChild(ui.outputBlock({ label: 'Length', value: bytes.length + ' bytes' }));
                output.appendChild(sec);
            } catch (e) {
                output.appendChild(ui.banner('error', e.message));
            }
        }
        input.input.addEventListener('input', refresh);

        // Run once to populate
        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({ label: 'Convert', onRun: refresh }));
        c.body.appendChild(btnRow);
        return c;
    }

    // ---------- Random bytes ----------
    function _randomCard() {
        const c = ui.card({ num: '06.B', title: 'Random bytes' });

        const numBytes = ui.numberField({
            id: 'rand-n', label: 'Bytes', defaultValue: 32, min: 1, max: 4096,
        });
        c.body.appendChild(numBytes);

        const seed = ui.byteField({
            id: 'rand-seed', label: 'Seed (optional)',
            defaultEncoding: 'utf8',
            help: 'If provided, output is deterministic (SHA-256 ratchet). NOT cryptographic; use only for reproducible test vectors.',
        });
        c.body.appendChild(seed);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Generate',
            onRun: async () => {
                output.innerHTML = '';
                try {
                    const n = numBytes.getValue();
                    const seedBytes = seed.getBytes();
                    let bytes;
                    if (seedBytes.length > 0) {
                        bytes = await enc.seededBytes(seedBytes, n);
                    } else {
                        bytes = enc.randomBytes(n);
                    }
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Random', value: bytes, encoding: 'hex' }));
                    sec.appendChild(ui.outputBlock({ label: 'Base64', value: bytes, encoding: 'base64' }));
                    if (seedBytes.length > 0) {
                        sec.appendChild(ui.banner('warning',
                            'Deterministic mode active. Same seed will always produce the same bytes. ' +
                            'Do NOT use these as production keys.'));
                    }
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    // ---------- Bit-flip / tamper ----------
    function _tamperCard() {
        const c = ui.card({ num: '06.C', title: 'Tamper / bit-flip' });
        const note = ui.banner('warning',
            'Useful for testing AEAD authentication: flip one bit in a ciphertext, ' +
            'then watch the tag verification fail.');
        c.body.appendChild(note);

        const input = ui.byteField({
            id: 'tam-in', label: 'Input bytes', multiline: true, required: true,
            defaultEncoding: 'hex',
        });
        const byteIndex = ui.numberField({
            id: 'tam-byte', label: 'Byte index', defaultValue: 0, min: 0,
            help: '0-indexed. Must be less than input length.',
        });
        const bitIndex = ui.numberField({
            id: 'tam-bit', label: 'Bit (0-7)', defaultValue: 0, min: 0, max: 7,
            help: '0 = least-significant bit',
        });
        c.body.appendChild(input);
        c.body.appendChild(byteIndex);
        c.body.appendChild(bitIndex);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Flip the bit',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const orig = input.getBytes();
                    const bi = byteIndex.getValue();
                    const bit = bitIndex.getValue();
                    if (bi < 0 || bi >= orig.length) {
                        throw new Error(`byte index ${bi} out of range (input has ${orig.length} bytes)`);
                    }
                    const out = new Uint8Array(orig);
                    const oldByte = out[bi];
                    out[bi] = oldByte ^ (1 << bit);
                    const sec = ui.el('div', { class: 'output-section' });
                    sec.appendChild(ui.outputBlock({ label: 'Tampered output', value: out, encoding: 'hex' }));
                    sec.appendChild(ui.outputBlock({
                        label: `Byte ${bi}: ${oldByte.toString(16).padStart(2,'0')} → ${out[bi].toString(16).padStart(2,'0')}`,
                        value: `bit ${bit} flipped`,
                    }));
                    output.appendChild(sec);
                } catch (e) { output.appendChild(ui.banner('error', e.message)); }
            },
        }));
        c.body.appendChild(btnRow);
        return c;
    }

    // ---------- Constant-time compare ----------
    function _compareCard() {
        const c = ui.card({ num: '06.D', title: 'Compare bytes (constant-time)' });

        const a = ui.byteField({ id: 'cmp-a', label: 'A', multiline: true, defaultEncoding: 'hex' });
        const b = ui.byteField({ id: 'cmp-b', label: 'B', multiline: true, defaultEncoding: 'hex' });
        c.body.appendChild(a);
        c.body.appendChild(b);

        const output = ui.el('div');
        c.body.appendChild(output);

        const btnRow = ui.el('div', { class: 'btn-row' });
        btnRow.appendChild(ui.runButton({
            label: 'Compare',
            onRun: () => {
                output.innerHTML = '';
                try {
                    const aB = a.getBytes();
                    const bB = b.getBytes();
                    const equal = enc.bytesEqual(aB, bB);
                    const sec = ui.el('div', { class: 'output-section' });
                    if (equal) {
                        sec.appendChild(ui.banner('ok', `Equal — both inputs are ${aB.length} bytes and bytewise identical.`));
                    } else if (aB.length !== bB.length) {
                        sec.appendChild(ui.banner('error',
                            `NOT equal — A is ${aB.length} bytes, B is ${bB.length} bytes (lengths differ).`));
                    } else {
                        // Find first differing byte for debug help.
                        let firstDiff = -1;
                        for (let i = 0; i < aB.length; i++) {
                            if (aB[i] !== bB[i]) { firstDiff = i; break; }
                        }
                        sec.appendChild(ui.banner('error',
                            `NOT equal — both ${aB.length} bytes, differ starting at byte ${firstDiff} ` +
                            `(0x${aB[firstDiff].toString(16).padStart(2,'0')} vs ` +
                            `0x${bB[firstDiff].toString(16).padStart(2,'0')}).`));
                    }
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
    global.cryptolab.tabs.tools = { build };

})(typeof window !== 'undefined' ? window : globalThis);
