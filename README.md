# cryptolab

A primitive-level cryptographic instrumentation tool for engineers
working on, integrating, or debugging crypto code. Runs entirely in
your browser — paste keys and data, see exact bytes out.

**Live demo:** *(set up by deploying to GitHub Pages — see below)*

---

## What it's for

You're implementing AES-CBC on an embedded target. You want to verify
your output against a reference. Right now you'd open three terminal
tabs, write a Python one-liner using `pycryptodome`, paste hex back and
forth, and probably make a mistake somewhere. cryptolab is the page
that replaces all of that.

Specifically:

- **Generate test vectors.** Pick parameters, get exact bytes out, copy
  in any encoding you want.
- **Verify your implementation.** Paste your output and the reference,
  use the constant-time compare tool to see where they differ.
- **Inspect what someone gave you.** Decrypt with a key, see structured
  results. Try different padding modes, IV lengths, AAD configurations.
- **Debug interop.** "My library produces this; theirs produces that."
  Run both inputs through the same primitive here and find which
  parameter is wrong.

This is **not** a "play with crypto" toy. It assumes you know what GCM
is and why you wouldn't reuse a nonce. It surfaces parameters explicitly
rather than picking sensible defaults silently.

## What it covers

| Tab | Algorithms |
|-----|-----------|
| **Symmetric** | AES-128/192/256 in CBC, CTR, ECB · ChaCha20 (raw stream) |
| **AEAD** | AES-GCM · ChaCha20-Poly1305 (RFC 8439) · XChaCha20-Poly1305 |
| **Hash & MAC** | SHA-1/224/256/384/512, SHA-512/256 · SHA3-224/256/384/512, Keccak-256 · BLAKE2b/2s, BLAKE3 · HMAC over any of the above · KMAC-128/256 (NIST SP 800-185) |
| **KDF** | PBKDF2 · HKDF (RFC 5869) · scrypt (RFC 7914) · Argon2id/i/d (RFC 9106) |
| **Asymmetric** | RSA-OAEP / RSA-PSS / RSASSA-PKCS1-v1_5 · ECDSA over P-256/384/521 · Ed25519 (RFC 8032) · X25519 (RFC 7748) · secp256k1 (Bitcoin/Ethereum) |
| **Tools** | Encoding converter (hex ↔ base64 ↔ UTF-8) · Random/seeded bytes · Bit-flip tamper · Constant-time compare |

Where **Web Crypto** provides the algorithm natively (SHA-1/256/384/512,
HMAC, AES-CBC/CTR/GCM, PBKDF2, ECDSA P-curves, RSA), cryptolab uses it
directly. Everything else uses the audited, MIT-licensed
[`@noble`](https://github.com/paulmillr/noble-curves) libraries vendored
into `vendor/`.

## What's NOT in this build

To set expectations about scope:

- **NIST CAVS `.rsp` file parsing** — tedious format with many
  algorithm-specific variants. Easy to add; not done yet.
- **Round-by-round AES visualization** — slick demo but a lot of UI
  work. Not done.
- **Side-channel / constant-time analysis** — wrong category of tool;
  use [`dudect`](https://github.com/oreparaz/dudect) or `ctgrind`.
- **Hardware test vector formats** (HSM compliance suites) — too niche
  to guess at.
- **Post-quantum** (Kyber, Dilithium) — Web Crypto doesn't have them
  and the WASM bundles are large.
- **JSON test-vector export** — coming, but not in this initial cut.

## Verifying correctness

Every primitive is validated against published test vectors from the
relevant standard. Run the KAT suite with Node:

```bash
node tests/kat.mjs
```

Coverage includes vectors from FIPS 180-4, FIPS 202, RFC 4231 (HMAC),
RFC 6070 (PBKDF2), RFC 5869 (HKDF), RFC 7914 (scrypt), RFC 8032
(Ed25519), RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305), and NIST
SP 800-38A (AES-CBC) / 800-38D (AES-GCM).

## Privacy

Everything happens in your browser. Keys, plaintexts, and signatures
**never leave your device**. There is no server. GitHub Pages only
serves static files. After the initial page load, no further network
requests are made — open dev tools and confirm.

The page also computes a SHA-256 of all loaded JavaScript and shows it
in the footer. Run `bash verify.sh https://<your-deploy-url>/` to
confirm the deployed bytes match what's in this repo.

## Deploying to GitHub Pages

The repository ships with `.github/workflows/pages.yml` which
auto-publishes on every push to `main`. To enable:

1. Fork or clone the repo, push to your account.
2. Go to your repo's **Settings → Pages**.
3. Under **Source**, choose **GitHub Actions**.
4. The next push triggers a deploy. The site appears at:
   ```
   https://<your-username>.github.io/<repo-name>/
   ```

The workflow includes an `INTEGRITY.txt` consistency check: if the JS
bundle changes but `INTEGRITY.txt` isn't regenerated, deployment fails
loudly rather than silently breaking the page-integrity verification.

## Running locally

Web Crypto requires a "secure context", so serve over `localhost`:

```bash
python3 -m http.server 8080
# open http://localhost:8080/
```

## Repo layout

```
cryptolab/
├── index.html              Single-page UI
├── app.js                  Tab controller + integrity hash
├── core/
│   ├── encoding.js         hex / base64 / UTF-8 + auto-detection
│   ├── symmetric.js        AES (CBC/CTR/ECB) + ChaCha20
│   ├── aead.js             AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305
│   ├── hash.js             SHA family, HMAC, KMAC, BLAKE
│   ├── kdf.js              PBKDF2, HKDF, scrypt, Argon2
│   └── asymmetric.js       RSA, ECDSA, Ed25519, X25519, secp256k1
├── ui/
│   ├── components.js       Reusable byte-input field, output blocks
│   └── tabs/               One file per primitive family
├── vendor/
│   ├── noble-hashes.js     Bundled @noble/hashes (SHA3, KMAC, BLAKE)
│   ├── noble-curves.js     Bundled @noble/curves (Ed25519, X25519, secp256k1)
│   └── noble-ciphers.js    Bundled @noble/ciphers (ChaCha, XChaCha, AES)
├── tests/
│   └── kat.mjs             Known-answer tests against published vectors
├── INTEGRITY.txt           SHA-256 of the JS bundle
├── verify.sh               Recompute integrity from any URL or local copy
└── .github/workflows/
    └── pages.yml           Auto-deploy with integrity gate
```

## Aesthetic note

Where seal (the encryption tool) goes for "warm archival paper, wax
seal" — appropriate for *trust* — cryptolab goes for "modernized
1985 lab instrument": phosphor-green on black, hex grid background,
JetBrains Mono throughout, color reserved for state (green = ok,
amber = warning, red = error). Different problem, different visual
language.

## License

MIT. Use it however you want. The bundled noble libraries are also
MIT — see `node_modules/@noble/*/LICENSE` if you re-bundle from source.

## Adding more

The architecture is built for extension. To add a new primitive:

1. Add the operation function to the relevant `core/*.js` module
   following the existing `{ ok, output, params }` return convention.
2. Add a known-answer test in `tests/kat.mjs` against a published
   vector — this is how you prove correctness, not a round-trip test.
3. Add a card to the relevant `ui/tabs/*.js` using the shared
   `byteField`, `selectField`, `numberField`, `outputBlock` components.
4. Regenerate `INTEGRITY.txt` and commit.
