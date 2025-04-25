#!/bin/bash
set -e

BINARY="./busybox-1.36.1/busybox"

# Step 1: Compute the hash using the built binary
HASH=$($BINARY verifyhash --output-hash)
echo "Computed hash: $HASH"

# Step 2: Convert hash to binary
HASH_BIN=$(mktemp)
echo "$HASH" | xxd -r -p > "$HASH_BIN"

# Step 3: Find .hashsig section and its offset
OFFSET_HEX=$(readelf -S "$BINARY" | awk '
  $2 == ".hashsig" {
    print $5
    exit
  }')

if [[ -z "$OFFSET_HEX" ]]; then
    echo "Failed to locate .hashsig section in ELF."
    exit 1
fi

OFFSET=$((16#$OFFSET_HEX))
echo "Patching .hashsig section at offset 0x$OFFSET_HEX..."

# Step 4: Patch the binary with the known-good hash
dd if="$HASH_BIN" of="$BINARY" bs=1 seek="$OFFSET" conv=notrunc status=none
echo "✅ Patched known-good hash into binary."

rm "$HASH_BIN"

