#!/bin/sh
set -eu
umask 077

# The root token arrives only on stdin from the operator's hidden prompt. It is
# never a command argument, compose environment value, file, or log field.
IFS= read -r BAO_TOKEN
[ -n "$BAO_TOKEN" ] || { echo "missing bootstrap token" >&2; exit 1; }
export BAO_TOKEN

if ! bao secrets list -format=json | grep -q '"secret/"'; then
  bao secrets enable -path=secret -version=2 kv >/dev/null
fi
if ! bao secrets list -format=json | grep -q '"transit/"'; then
  bao secrets enable transit >/dev/null
fi
if ! bao read transit/keys/as-certification >/dev/null 2>&1; then
  bao write -f transit/keys/as-certification type=ed25519 exportable=false \
    allow_plaintext_backup=false >/dev/null
fi
if ! bao read transit/keys/tofu-state >/dev/null 2>&1; then
  bao write -f transit/keys/tofu-state type=aes256-gcm96 exportable=false \
    allow_plaintext_backup=false auto_rotate_period=720h >/dev/null
fi
for policy in provisioner certifier runtime-as model-broker; do
  bao policy write "$policy" "/openbao/bootstrap/policies/$policy.hcl" >/dev/null
done
unset BAO_TOKEN
echo "OpenBao engines and least-privilege Andyur policies configured"
