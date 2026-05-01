// app.js — top-level controller for cryptolab.
//
// Responsibilities:
//   1. Wire tab clicks to swap visible panel
//   2. Lazy-build each tab's DOM the first time it's activated (saves
//      perceived load time on first paint)
//   3. Compute a SHA-256 of all loaded JS files for the integrity badge
//      in the footer (same idea as seal — proves the deployed bytes
//      match the source repo)

(function () {
    'use strict';

    const cl = window.cryptolab;
    if (!cl || !cl.tabs) {
        console.error('cryptolab modules failed to load');
        return;
    }

    // ---------- environment check ----------
    if (!window.crypto || !window.crypto.subtle) {
        const msg = document.createElement('div');
        msg.style.cssText = 'padding:30px; color:#ff6b6b; border:1px solid #ff6b6b;';
        msg.textContent = 'Web Crypto API is not available. cryptolab requires a modern browser served over HTTPS or localhost.';
        document.getElementById('panels').appendChild(msg);
        return;
    }
    if (!window.NobleHashes || !window.NobleCurves || !window.NobleCiphers) {
        const msg = document.createElement('div');
        msg.style.cssText = 'padding:30px; color:#ff6b6b; border:1px solid #ff6b6b;';
        msg.textContent = 'Vendored crypto libraries failed to load. Check the browser console for details.';
        document.getElementById('panels').appendChild(msg);
        return;
    }

    // ---------- tab management ----------
    const tabButtons = document.querySelectorAll('.tab');
    const panelsContainer = document.getElementById('panels');
    const builtPanels = {};

    function activateTab(name) {
        for (const t of tabButtons) {
            t.classList.toggle('active', t.dataset.tab === name);
        }
        // Hide all panels.
        for (const k in builtPanels) {
            builtPanels[k].classList.toggle('active', k === name);
        }
        // Build on demand.
        if (!builtPanels[name]) {
            const tab = cl.tabs[name];
            if (!tab) {
                console.error('unknown tab:', name);
                return;
            }
            const panel = tab.build();
            panel.classList.add('panel', 'active');
            panelsContainer.appendChild(panel);
            builtPanels[name] = panel;
        } else {
            builtPanels[name].classList.add('active');
        }
    }

    for (const t of tabButtons) {
        t.addEventListener('click', () => activateTab(t.dataset.tab));
    }

    // Activate the default tab on load.
    const defaultTab = document.querySelector('.tab.active');
    activateTab(defaultTab ? defaultTab.dataset.tab : 'symmetric');

    // ---------- integrity hash ----------
    // Compute SHA-256 of all loaded scripts (vendor + core + ui + app)
    // concatenated, and show a short prefix in the footer. Matches the
    // pattern used in seal: a published INTEGRITY.txt holds the expected
    // value, and a verify.sh script lets users confirm a deployment.
    async function computeIntegrity() {
        const target = document.getElementById('integrityHash');
        if (!target) return;
        try {
            const scripts = [
                'vendor/noble-hashes.js', 'vendor/noble-curves.js', 'vendor/noble-ciphers.js',
                'core/encoding.js', 'core/symmetric.js', 'core/aead.js',
                'core/hash.js', 'core/kdf.js', 'core/asymmetric.js',
                'ui/components.js',
                'ui/tabs/symmetric.js', 'ui/tabs/aead.js', 'ui/tabs/hash.js',
                'ui/tabs/kdf.js', 'ui/tabs/asymmetric.js', 'ui/tabs/tools.js',
                'app.js',
            ];
            const buffers = [];
            let total = 0;
            for (const url of scripts) {
                const r = await fetch(url, { cache: 'force-cache' });
                if (!r.ok) throw new Error(`${url}: ${r.status}`);
                const buf = await r.arrayBuffer();
                buffers.push(buf);
                total += buf.byteLength;
            }
            const all = new Uint8Array(total);
            let off = 0;
            for (const buf of buffers) {
                all.set(new Uint8Array(buf), off);
                off += buf.byteLength;
            }
            const digest = await crypto.subtle.digest('SHA-256', all);
            const hex = Array.from(new Uint8Array(digest))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            target.textContent = 'integrity ' + hex.slice(0, 16) + '…';
            target.title = 'SHA-256 of loaded scripts: ' + hex +
                '\nCompare against INTEGRITY.txt in the repo.';
        } catch (err) {
            target.textContent = 'integrity unavailable';
            target.title = 'Integrity hash could not be computed: ' + err.message;
        }
    }
    if (window.requestIdleCallback) {
        requestIdleCallback(computeIntegrity, { timeout: 2000 });
    } else {
        setTimeout(computeIntegrity, 500);
    }

    // ---------- ready signal ----------
    const readyText = document.getElementById('readyText');
    if (readyText) readyText.textContent = 'READY';

})();
