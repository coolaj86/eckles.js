#/bin/bash
set -e

echo ""
echo ""
node bin/eckles.js fixtures/privkey-ec-p256.sec1.pem
node bin/eckles.js fixtures/privkey-ec-p256.pkcs8.pem
node bin/eckles.js fixtures/pub-ec-p256.spki.pem

echo ""
echo ""
node bin/eckles.js fixtures/privkey-ec-p384.sec1.pem
node bin/eckles.js fixtures/privkey-ec-p384.pkcs8.pem
node bin/eckles.js fixtures/pub-ec-p384.spki.pem

echo ""
echo ""
node bin/eckles.js fixtures/privkey-ec-p256.jwk sec1
node bin/eckles.js fixtures/privkey-ec-p256.jwk pkcs8
node bin/eckles.js fixtures/pub-ec-p256.jwk spki

echo ""
echo ""
node bin/eckles.js fixtures/privkey-ec-p384.jwk sec1
node bin/eckles.js fixtures/privkey-ec-p384.jwk pkcs8
node bin/eckles.js fixtures/pub-ec-p384.jwk spki

echo ""
