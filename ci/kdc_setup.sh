#!/usr/bin/env bash
# Stand up a TEST.LOCAL MIT KDC on 127.0.0.1:88 with a known principal set.
set -e

mkdir -p /tmp/cerber-kdc/db

cat > /tmp/cerber-kdc/kdc.conf <<'EOF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    TEST.LOCAL = {
        database_name = /tmp/cerber-kdc/db/principal
        key_stash_file = /tmp/cerber-kdc/db/stash
        max_life = 10h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    }
EOF

cat > /tmp/cerber-kdc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_kdc = false

[realms]
    TEST.LOCAL = {
        kdc = 127.0.0.1:88
    }
EOF

export KRB5_CONFIG=/tmp/cerber-kdc/krb5.conf KRB5_KDC_PROFILE=/tmp/cerber-kdc/kdc.conf

kdb5_util create -s -r TEST.LOCAL -P masterpass123

kadmin.local -q "addprinc -pw Passw0rd123 alice"
kadmin.local -q "addprinc -pw Summer2024! bob"
kadmin.local -q "modprinc -requires_preauth bob"
kadmin.local -q "addprinc -pw Service99! svc-web"
kadmin.local -q "addprinc -pw Service99! HTTP/web.test.local"

krb5kdc -P /tmp/cerber-kdc/kdc.pid
echo "kdc up"
