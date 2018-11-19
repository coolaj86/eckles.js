#/bin/bash

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
