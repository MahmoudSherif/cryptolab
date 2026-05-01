#!/usr/bin/env bash
# verify.sh — verify that a deployed cryptolab page is running unmodified code.
#
# Usage:
#   ./verify.sh                                   # verify the current folder
#   ./verify.sh https://you.github.io/cryptolab/  # verify a deployed site
#
# Recomputes SHA-256 of the JS bundle (vendored libs + core + UI tabs + app),
# compares against INTEGRITY.txt. The deployed page also computes and shows
# this hash in its footer — if all three match, the bytes you're running
# are exactly what's in the repository.

set -eu

SOURCE="${1:-.}"
SCRIPTS=(
    "vendor/noble-hashes.js"
    "vendor/noble-curves.js"
    "vendor/noble-ciphers.js"
    "core/encoding.js"
    "core/symmetric.js"
    "core/aead.js"
    "core/hash.js"
    "core/kdf.js"
    "core/asymmetric.js"
    "ui/components.js"
    "ui/tabs/symmetric.js"
    "ui/tabs/aead.js"
    "ui/tabs/hash.js"
    "ui/tabs/kdf.js"
    "ui/tabs/asymmetric.js"
    "ui/tabs/tools.js"
    "app.js"
)

cleanup() { [ -n "${TMPDIR:-}" ] && [ -d "${TMPDIR:-}" ] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

case "$SOURCE" in
    http://*|https://*)
        BASE="${SOURCE%/}"
        TMPDIR=$(mktemp -d)
        echo "fetching from $BASE/"
        for f in "${SCRIPTS[@]}"; do
            target="$TMPDIR/$f"
            mkdir -p "$(dirname "$target")"
            if ! curl -sSf -o "$target" "$BASE/$f"; then
                echo "error: failed to fetch $BASE/$f" >&2
                exit 1
            fi
            printf "  fetched %-30s (%s bytes)\n" "$f" "$(wc -c < "$target")"
        done
        PREFIX="$TMPDIR"
        ;;
    *)
        PREFIX="${SOURCE%/}"
        if [ ! -d "$PREFIX" ]; then
            echo "error: $PREFIX is not a directory" >&2
            exit 1
        fi
        for f in "${SCRIPTS[@]}"; do
            if [ ! -f "$PREFIX/$f" ]; then
                echo "error: $PREFIX/$f does not exist" >&2
                exit 1
            fi
        done
        ;;
esac

# Concatenate all files in order and hash.
PATHS=""
for f in "${SCRIPTS[@]}"; do
    PATHS="$PATHS $PREFIX/$f"
done
HASH=$(cat $PATHS | sha256sum | awk '{print $1}')

echo
echo "computed SHA-256:"
echo "  $HASH"

INTEGRITY_FILE="$(dirname "$0")/INTEGRITY.txt"
if [ -f "$INTEGRITY_FILE" ]; then
    EXPECTED=$(grep -oE '^[a-f0-9]{64}' "$INTEGRITY_FILE" | head -1 || echo "")
    echo
    echo "expected from INTEGRITY.txt:"
    echo "  $EXPECTED"
    echo
    if [ "$HASH" = "$EXPECTED" ]; then
        echo "MATCH — these files match the published integrity hash."
        exit 0
    else
        echo "MISMATCH — files differ from INTEGRITY.txt."
        echo
        echo "Possible causes:"
        echo "  - The repo has changed since INTEGRITY.txt was written"
        echo "    (regenerate it; see below)"
        echo "  - The deployed site has been tampered with"
        echo
        echo "To regenerate INTEGRITY.txt locally:"
        echo "  cd cryptolab"
        echo "  HASH=\$(cat ${SCRIPTS[*]} | sha256sum | awk '{print \$1}')"
        echo "  sed -i \"1s/^[a-f0-9]\\{64\\}/\$HASH/\" INTEGRITY.txt"
        exit 1
    fi
else
    echo
    echo "(no INTEGRITY.txt found at $INTEGRITY_FILE — write one with:)"
    echo "  echo \"$HASH  cryptolab\" > $INTEGRITY_FILE"
fi
