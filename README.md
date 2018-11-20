eckles.js
=========

ECDSA tools. Lightweight. Zero Dependencies. Universal compatibility.

* [x] PEM-to-JWK
* [ ] JWK-to-PEM (partial)

### PEM-to-JWK

* [x] SEC1/X9.62, PKCS#8, SPKI/PKIX
* [x] P-256 (prime256v1, secp256r1), P-384 (secp384r1)

```js
var eckles = require('eckles');
var pem = require('fs').readFileSync('./fixtures/privkey-ec-p256.sec1.pem', 'ascii')

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

### JWK-to-PEM

* [x] SEC1/X9.62
* [x] P-256 (prime256v1, secp256r1), P-384 (secp384r1)


```js
eckles.export({ jwk: jwk }).then(function (pem) {
  // PEM in sec1 (x9.62) format
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

<!--
```js
eckles.exportSEC1(jwk).then(function (pem) {
  // PEM in sec1 (x9.62) format
  console.log(pem);
});
```
-->

Goals
-----

* Zero Dependencies
* Focused support for P-256 and P-384, which are already universally supported.
* Convert both ways
* Browser support as well
