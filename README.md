eckles.js
=========

Sponsored by [Root](https://therootcompany.com).
Built for [ACME.js](https://git.coolaj86.com/coolaj86/acme.js)
and [Greenlock.js](https://git.coolaj86.com/coolaj86/greenlock.js)

ECDSA (elliptic curve) tools. Lightweight. Zero Dependencies. Universal compatibility.

* [x] PEM-to-JWK
* [x] JWK-to-PEM
* [x] SSH "pub" format

This project is fully functional and tested (and the code is pretty clean).

It is considered to be complete, but if you find a bug please open an issue.

## PEM-to-JWK

* [x] SEC1/X9.62, PKCS#8, SPKI/PKIX
* [x] P-256 (prime256v1, secp256r1), P-384 (secp384r1)
* [x] SSH (RFC4716), (RFC 4716/SSH2)

```js
var eckles = require('eckles');
var pem = require('fs')
  .readFileSync('./node_modles/eckles/fixtures/privkey-ec-p256.sec1.pem', 'ascii');

eckles.import({ pem: pem }).then(function (jwk) {
  console.log(jwk);
});
```

```js
{
  "kty": "EC",
  "crv": "P-256",
  "d": "iYydo27aNGO9DBUWeGEPD8oNi1LZDqfxPmQlieLBjVQ",
  "x": "IT1SWLxsacPiE5Z16jkopAn8_-85rMjgyCokrnjDft4",
  "y": "mP2JwOAOdMmXuwpxbKng3KZz27mz-nKWIlXJ3rzSGMo"
}
```

## JWK-to-PEM

* [x] SEC1/X9.62, PKCS#8, SPKI/PKIX
* [x] P-256 (prime256v1, secp256r1), P-384 (secp384r1)
* [x] SSH (RFC4716), (RFC 4716/SSH2)

```js
var eckles = require('eckles');
var jwk = require('eckles/fixtures/privkey-ec-p256.jwk.json');

eckles.export({ jwk: jwk }).then(function (pem) {
  // PEM in SEC1 (x9.62) format
  console.log(pem);
});
```

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIImMnaNu2jRjvQwVFnhhDw/KDYtS2Q6n8T5kJYniwY1UoAoGCCqGSM49
AwEHoUQDQgAEIT1SWLxsacPiE5Z16jkopAn8/+85rMjgyCokrnjDft6Y/YnA4A50
yZe7CnFsqeDcpnPbubP6cpYiVcnevNIYyg==
-----END EC PRIVATE KEY-----
```

### Advanced Options

`format: 'pkcs8'`:

The default output format is `sec1`/`x9.62` (EC-specific format) is used for private keys.
Use `format: 'pkcs8'` to output in PKCS#8 format instead.

```js
eckles.export({ jwk: jwk, format: 'pkcs8' }).then(function (pem) {
  // PEM in PKCS#8 format
  console.log(pem);
});
```

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiYydo27aNGO9DBUW
eGEPD8oNi1LZDqfxPmQlieLBjVShRANCAAQhPVJYvGxpw+ITlnXqOSikCfz/7zms
yODIKiSueMN+3pj9icDgDnTJl7sKcWyp4Nymc9u5s/pyliJVyd680hjK
-----END PRIVATE KEY-----
```

`format: 'ssh'`:

Although SSH uses SEC1 for private keys, it uses ts own special non-ASN1 format
(affectionately known as rfc4716) for public keys. I got curious and then decided
to add this format as well.

To get the same format as you
would get with `ssh-keygen`, pass `ssh` as the format option:

```js
eckles.export({ jwk: jwk, format: 'ssh' }).then(function (pub) {
  // Special SSH2 Public Key format (RFC 4716)
  console.log(pub);
});
```

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCE9Uli8bGnD4hOWdeo5KKQJ/P/vOazI4MgqJK54w37emP2JwOAOdMmXuwpxbKng3KZz27mz+nKWIlXJ3rzSGMo= P-256@localhost
```

`public: 'true'`:

If a private key is used as input, a private key will be output.

If you'd like to output a public key instead you can pass `public: true` or `format: 'spki'`.

```js
eckles.export({ jwk: jwk, public: true }).then(function (pem) {
  // PEM in SPKI/PKIX format
  console.log(pem);
});
```

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIT1SWLxsacPiE5Z16jkopAn8/+85
rMjgyCokrnjDft6Y/YnA4A50yZe7CnFsqeDcpnPbubP6cpYiVcnevNIYyg==
-----END PUBLIC KEY-----
```

Testing
-------

All cases are tested in `test.sh`.

You can compare these keys to the ones that you get from OpenSSL, ssh-keygen, and WebCrypto:

```bash
# Generate EC P-256 Keypair
openssl ecparam -genkey -name prime256v1 -noout -out ./privkey-ec-p256.sec1.pem

# Export Public-only EC Key (as SPKI)
openssl ec -in ./privkey-ec-p256.sec1.pem -pubout -out ./pub-ec-p256.spki.pem

# Convert SEC1 (traditional) EC Keypair to PKCS8 format
openssl pkcs8 -topk8 -nocrypt -in ./privkey-ec-p256.sec1.pem -out ./privkey-ec-p256.pkcs8.pem

# Convert EC public key to SSH format
ssh-keygen -f ./pub-ec-p256.spki.pem -i -mPKCS8 > ./pub-ec-p256.ssh.pub
```

Goals of this project
-----

* Zero Dependencies
* Focused support for P-256 and P-384, which are already universally supported.
* Convert both ways
* Browser support as well (TODO)
* OpenSSL, ssh-keygen, and WebCrypto compatibility

Legal
-----

Licensed MPL-2.0

[Terms of Use](https://therootcompany.com/legal/#terms) |
[Privacy Policy](https://therootcompany.com/legal/#privacy)
