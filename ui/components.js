// ui/components.js — shared UI building blocks.
//
// Every tab uses these to render input fields, output blocks, and copy
// buttons consistently. The big idea: a "byte field" is an input where
// the user picks the encoding (hex / base64 / utf-8) via small tabs above
// the textarea. The component handles parsing + live byte-length display.

(function (global) {
    'use strict';

    const enc = global.cryptolab.encoding;

    // ---------- byte field ----------
    /**
     * Create a labeled input that accepts bytes encoded as hex/base64/utf-8.
     *
     * @param {Object} opts
     * @param {string} opts.id         - DOM id prefix
     * @param {string} opts.label
     * @param {boolean} opts.required
     * @param {string[]} opts.encodings - which encoding tabs to show (default: hex,b64,utf8)
     * @param {string} opts.defaultEncoding
     * @param {boolean} opts.multiline - use textarea instead of input
     * @param {string} opts.placeholder
     * @param {function} opts.onChange - (bytes, encoding, valid) => void
     * @param {string} opts.help        - optional help text below the field
     * @param {number} opts.minBytes / maxBytes - validation
     * @returns {HTMLElement} the field-row
     */
    function byteField(opts) {
        const id = opts.id;
        const encodings = opts.encodings || ['hex', 'base64', 'utf8'];
        let currentEncoding = opts.defaultEncoding || encodings[0];

        const row = el('div', { class: 'field-row' });

        const label = el('label', { class: 'field-label', for: id + '-input' });
        label.textContent = opts.label;
        if (opts.required) {
            const req = el('span', { class: 'req' });
            req.textContent = '*';
            label.appendChild(req);
        }
        row.appendChild(label);

        const wrap = el('div', { class: 'input-wrap' });

        // encoding tabs
        const encTabs = el('div', { class: 'encoding-tabs' });
        const encButtons = {};
        for (const e of encodings) {
            const b = el('button', {
                class: 'encoding-tab' + (e === currentEncoding ? ' active' : ''),
                type: 'button',
                'data-enc': e,
            });
            b.textContent = encodingLabel(e);
            b.addEventListener('click', () => switchEncoding(e));
            encTabs.appendChild(b);
            encButtons[e] = b;
        }
        wrap.appendChild(encTabs);

        // input
        const input = opts.multiline
            ? el('textarea', { id: id + '-input', placeholder: opts.placeholder || '' })
            : el('input', { type: 'text', id: id + '-input', placeholder: opts.placeholder || '', autocomplete: 'off', spellcheck: 'false' });
        wrap.appendChild(input);

        // meta line: byte count + actions
        const meta = el('div', { class: 'field-meta' });
        const metaText = el('span');
        metaText.textContent = '0 bytes';
        meta.appendChild(metaText);
        const metaActions = el('span', { class: 'actions' });
        meta.appendChild(metaActions);
        wrap.appendChild(meta);

        if (opts.help) {
            const help = el('div', { class: 'field-meta', style: 'margin-top: 2px;' });
            help.textContent = opts.help;
            wrap.appendChild(help);
        }

        row.appendChild(wrap);

        // ---------- behavior ----------
        function switchEncoding(newEnc) {
            // Re-encode current bytes into the new encoding.
            const v = input.value;
            try {
                if (v.trim()) {
                    const { bytes } = enc.parseInput(v, currentEncoding);
                    input.value = enc.formatBytes(bytes, newEnc);
                }
            } catch (e) {
                // If current value can't be parsed, just clear and switch.
                input.value = '';
            }
            currentEncoding = newEnc;
            for (const e in encButtons) {
                encButtons[e].classList.toggle('active', e === newEnc);
            }
            update();
        }

        function getBytes() {
            const v = input.value;
            if (!v.trim() && !opts.required) return new Uint8Array(0);
            return enc.parseInput(v, currentEncoding).bytes;
        }

        function setBytes(bytes) {
            input.value = enc.formatBytes(bytes, currentEncoding);
            update();
        }

        function update() {
            try {
                const bytes = getBytes();
                metaText.textContent = bytes.length + ' bytes';
                meta.classList.remove('error');
                let valid = true;
                if (opts.minBytes != null && bytes.length < opts.minBytes) {
                    metaText.textContent += ` (min ${opts.minBytes})`;
                    meta.classList.add('error');
                    valid = false;
                }
                if (opts.maxBytes != null && bytes.length > opts.maxBytes) {
                    metaText.textContent += ` (max ${opts.maxBytes})`;
                    meta.classList.add('error');
                    valid = false;
                }
                if (opts.requireBytes != null && bytes.length !== opts.requireBytes) {
                    metaText.textContent += ` (need exactly ${opts.requireBytes})`;
                    meta.classList.add('error');
                    valid = false;
                }
                if (opts.onChange) opts.onChange(bytes, currentEncoding, valid);
            } catch (e) {
                metaText.textContent = 'invalid: ' + e.message;
                meta.classList.add('error');
                if (opts.onChange) opts.onChange(null, currentEncoding, false);
            }
        }

        input.addEventListener('input', update);

        return Object.assign(row, {
            getBytes, setBytes,
            getEncoding: () => currentEncoding,
            setEncoding: switchEncoding,
            input,
            metaActions,
            update,
        });
    }

    function encodingLabel(e) {
        return { hex: 'HEX', base64: 'BASE64', base64url: 'B64URL', utf8: 'UTF-8' }[e] || e;
    }

    // ---------- text/select fields ----------
    function selectField({ id, label, options, defaultValue, onChange, help }) {
        const row = el('div', { class: 'field-row tight' });
        const lbl = el('label', { class: 'field-label', for: id });
        lbl.textContent = label;
        row.appendChild(lbl);

        const wrap = el('div', { class: 'input-wrap' });
        const sel = el('select', { id });
        for (const opt of options) {
            const o = el('option', { value: typeof opt === 'string' ? opt : opt.value });
            o.textContent = typeof opt === 'string' ? opt : opt.label;
            sel.appendChild(o);
        }
        if (defaultValue) sel.value = defaultValue;
        if (onChange) sel.addEventListener('change', () => onChange(sel.value));
        wrap.appendChild(sel);
        if (help) {
            const h = el('div', { class: 'field-meta' });
            h.textContent = help;
            wrap.appendChild(h);
        }
        row.appendChild(wrap);
        return Object.assign(row, { select: sel, getValue: () => sel.value, setValue: v => sel.value = v });
    }

    function numberField({ id, label, defaultValue, min, max, step, help }) {
        const row = el('div', { class: 'field-row tight' });
        const lbl = el('label', { class: 'field-label', for: id });
        lbl.textContent = label;
        row.appendChild(lbl);

        const wrap = el('div', { class: 'input-wrap' });
        const inp = el('input', { type: 'number', id, value: defaultValue });
        if (min != null) inp.min = min;
        if (max != null) inp.max = max;
        if (step != null) inp.step = step;
        wrap.appendChild(inp);
        if (help) {
            const h = el('div', { class: 'field-meta' });
            h.textContent = help;
            wrap.appendChild(h);
        }
        row.appendChild(wrap);
        return Object.assign(row, { input: inp,
            getValue: () => Number(inp.value),
            setValue: v => inp.value = v });
    }

    // ---------- output ----------
    function outputBlock({ label, value, encoding, color, copyAs }) {
        const block = el('div', { class: 'output-block' });
        const lab = el('div', { class: 'output-label' });
        const labText = el('span');
        labText.textContent = label;
        lab.appendChild(labText);

        // copy buttons
        const acts = el('span', { style: 'display:flex; gap:6px;' });
        const copyTargets = copyAs || (encoding ? [encoding, encoding === 'hex' ? 'base64' : 'hex'] : ['hex']);
        for (const target of copyTargets) {
            const btn = el('button', { class: 'mini-btn', type: 'button' });
            btn.textContent = 'copy ' + encodingLabel(target);
            btn.addEventListener('click', async () => {
                let text;
                if (typeof value === 'string') {
                    text = value;
                } else if (value instanceof Uint8Array) {
                    text = enc.formatBytes(value, target);
                } else {
                    text = String(value);
                }
                try {
                    await navigator.clipboard.writeText(text);
                    btn.textContent = '✓ copied';
                    setTimeout(() => btn.textContent = 'copy ' + encodingLabel(target), 1200);
                } catch (e) {
                    btn.textContent = 'copy failed';
                }
            });
            acts.appendChild(btn);
        }
        lab.appendChild(acts);
        block.appendChild(lab);

        const val = el('div', { class: 'output-value' + (color ? ' ' + color : '') });
        if (value instanceof Uint8Array) {
            val.textContent = enc.formatBytes(value, encoding || 'hex');
        } else {
            val.textContent = String(value);
        }
        block.appendChild(val);
        return block;
    }

    function paramsTable(params) {
        const table = el('table', { class: 'params-table' });
        const tbody = el('tbody');
        for (const k in params) {
            const tr = el('tr');
            const td1 = el('td'); td1.textContent = k;
            const td2 = el('td'); td2.textContent = String(params[k]);
            tr.appendChild(td1); tr.appendChild(td2);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        return table;
    }

    function banner(kind, text) {
        const b = el('div', { class: 'banner ' + kind });
        const span = el('span');
        span.textContent = text;
        b.appendChild(span);
        return b;
    }

    // ---------- card / section ----------
    function card({ num, title, action }) {
        const c = el('div', { class: 'card' });
        const head = el('div', { class: 'card-head' });
        const lab = el('div', { class: 'label' });
        if (num) {
            const n = el('span', { class: 'num' });
            n.textContent = num;
            lab.appendChild(n);
        }
        const t = document.createTextNode(title);
        lab.appendChild(t);
        head.appendChild(lab);
        const body = el('div', { class: 'card-body' });
        c.appendChild(head);
        c.appendChild(body);
        return Object.assign(c, { head, body, addControl: (el) => head.appendChild(el) });
    }

    // ---------- run button ----------
    function runButton({ label, onRun }) {
        const btn = el('button', { class: 'btn-run', type: 'button' });
        btn.textContent = label;
        btn.addEventListener('click', async () => {
            btn.disabled = true;
            const orig = btn.textContent;
            btn.textContent = 'computing…';
            try {
                await onRun();
            } catch (e) {
                console.error(e);
                // The tab's UI is responsible for showing the error;
                // we just unfreeze the button.
            }
            btn.disabled = false;
            btn.textContent = orig;
        });
        return btn;
    }

    // ---------- DOM helper ----------
    function el(tag, attrs) {
        const e = document.createElement(tag);
        if (attrs) for (const k in attrs) {
            if (k === 'class') e.className = attrs[k];
            else e.setAttribute(k, attrs[k]);
        }
        return e;
    }

    // ---------- exports ----------
    global.cryptolab.ui = {
        byteField, selectField, numberField,
        outputBlock, paramsTable, banner,
        card, runButton, el,
    };

})(typeof window !== 'undefined' ? window : globalThis);
