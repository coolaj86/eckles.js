eckles.js
=========

ECDSA (elliptic curve) tools. Lightweight. Zero Dependencies. Universal compatibility.

* [x] PEM-to-JWK
* [x] JWK-to-PEM

## PEM-to-JWK

* [x] SEC1/X9.62, PKCS#8, SPKI/PKIX
* [x] P-256 (prime256v1, secp256r1), P-384 (secp384r1)

```js
var eckles = require('eckles');
var pem = require('fs').readFileSync('eckles/fixtures/privkey-ec-p256.sec1.pem', 'ascii');

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

#### Advanced

`format: 'pkcs8'`:

The default output format is `sec1`/`x9.62` (EC-specific format) is used for private keys.
Use `format: 'pkcs8'` to output in PKCS#8 format instead.

```js
eckles.export({ jwk: jwk, format: 'pkcs8' }).then(function (pem) {
  // PEM in PKCS#8 format
  console.log(pem);
});
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

Goals
-----

* Zero Dependencies
* Focused support for P-256 and P-384, which are already universally supported.
* Convert both ways
* Browser support as well
