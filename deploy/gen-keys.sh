#!/bin/sh
# Generate the official server's secrets: an Ed25519 signing key (seed +
# public key) and an admin token. Needs only openssl.
#
#   sh deploy/gen-keys.sh
#
# RUGEN_SIGNING_KEY and RUGEN_ADMIN_TOKEN are secret: Dokploy Environment tab
# only (keep a copy in a password manager). RUGEN_OFFICIAL_KEY is public:
# GitHub rugen-engine → Settings → Secrets and variables → Actions → Variables.
set -eu

command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

# hex string on stdin → raw bytes on stdout (POSIX: via octal printf escapes)
unhex() {
    fold -w2 | while read -r b; do printf "\\$(printf '%03o' "0x$b")"; done
}
# raw bytes on stdin → lowercase hex on stdout
tohex() {
    od -An -v -tx1 | tr -d ' \n'
}

seed=$(openssl rand -hex 32)
admin=$(openssl rand -hex 32)
# PKCS#8 wrapper of a raw Ed25519 seed, so openssl can derive the public key
pub=$(printf '302e020100300506032b657004220420%s\n' "$seed" | unhex \
    | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | tohex)

[ ${#pub} -eq 64 ] || { echo "could not derive the public key (openssl too old?)" >&2; exit 1; }

cat <<OUT
# --- secret: Dokploy → rugen server → Environment -----------------------------
RUGEN_SIGNING_KEY=$seed
RUGEN_ADMIN_TOKEN=$admin

# --- public: GitHub rugen-engine → Settings → Secrets and variables → Variables
RUGEN_OFFICIAL_KEY=$pub
OUT
