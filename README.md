eckles.js
=========

ECDSA tools. Lightweight. Zero Dependencies. Universal compatibility.

> I _just_ cleaned up the PEM-to-JWK functionality enough to publish.
> I also have the JWK-to-PEM functionality _mostly_ built, but not enough to publish.

* P-256 (prime256v1, secp256r1)
* P-384 (secp384r1)
* PKCS#8
* SEC1/X9.62
* PEM-to-JWK

```js
eckles.import({ pem: pem }).then(function (jwk) {
  console.log(jwk);
});
```

<!--
```js
eckles.export({ jwk: jwk }).then(function (pem) {
  // PEM in pkcs#8 format
  console.log(pem);
});
```

```js
eckles.exportSEC1(jwk).then(function (pem) {
  // PEM in sec1 (x9.62) format
  console.log(pem);
});
```
-->

Goals
-----

* Focused support for P-256 and P-384, which are already universally supported.
* Convert both ways
* Browser support as well
