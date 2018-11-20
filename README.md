eckles.js
=========

ECDSA tools. Lightweight. Zero Dependencies. Universal compatibility.

> I _just_ cleaned up the PEM-to-JWK functionality enough to publish.
> I also have the JWK-to-PEM functionality _mostly_ built, but not enough to publish.

* P-256 (prime256v1, secp256r1)
* P-384 (secp384r1)
* SPKI/PKIX
* PKCS#8
* SEC1/X9.62
* PEM-to-JWK
* JWK-to-PEM

```js
var eckles = require('eckles');
var pem = require('fs').readFileSync('./fixtures/privkey-ec-p256.sec1.pem', 'ascii')

eckles.import({ pem: pem }).then(function (jwk) {
  console.log(jwk);
  /*
  {
    "kty": "EC",
    "crv": "P-256",
    "d": "iYydo27aNGO9DBUWeGEPD8oNi1LZDqfxPmQlieLBjVQ",
    "x": "IT1SWLxsacPiE5Z16jkopAn8_-85rMjgyCokrnjDft4",
    "y": "mP2JwOAOdMmXuwpxbKng3KZz27mz-nKWIlXJ3rzSGMo"
  }
  */
});
```

```js
eckles.export({ jwk: jwk }).then(function (pem) {
  // PEM in pkcs#8 format
  console.log(pem);
});
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
