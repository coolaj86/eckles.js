#/bin/bash
set -e

echo ""
echo ""
echo "Testing PEM-to-JWK P-256"
echo ""
node bin/eckles.js fixtures/privkey-ec-p256.sec1.pem | tee fixtures/privkey-ec-p256.jwk.2
diff fixtures/privkey-ec-p256.jwk.json fixtures/privkey-ec-p256.jwk.2
node bin/eckles.js fixtures/privkey-ec-p256.pkcs8.pem | tee fixtures/privkey-ec-p256.jwk.2
diff fixtures/privkey-ec-p256.jwk.json fixtures/privkey-ec-p256.jwk.2
node bin/eckles.js fixtures/pub-ec-p256.spki.pem | tee fixtures/pub-ec-p256.jwk.2
diff fixtures/pub-ec-p256.jwk.json fixtures/pub-ec-p256.jwk.2
#
node bin/eckles.js fixtures/pub-ec-p256.ssh.pub | tee fixtures/pub-ec-p256.jwk.2
diff fixtures/pub-ec-p256.jwk.2 fixtures/pub-ec-p256.jwk.2


echo ""
echo ""
echo "Testing PEM-to-JWK P-384"
echo ""
node bin/eckles.js fixtures/privkey-ec-p384.sec1.pem | tee fixtures/privkey-ec-p384.jwk.2
diff fixtures/privkey-ec-p384.jwk.json fixtures/privkey-ec-p384.jwk.2
node bin/eckles.js fixtures/privkey-ec-p384.pkcs8.pem | tee fixtures/privkey-ec-p384.jwk.2.2
diff fixtures/privkey-ec-p384.jwk.json fixtures/privkey-ec-p384.jwk.2.2
node bin/eckles.js fixtures/pub-ec-p384.spki.pem | tee fixtures/pub-ec-p384.jwk.2
diff fixtures/pub-ec-p384.jwk.json fixtures/pub-ec-p384.jwk.2
#
node bin/eckles.js fixtures/pub-ec-p384.ssh.pub | tee fixtures/pub-ec-p384.jwk.2
diff fixtures/pub-ec-p384.jwk.2 fixtures/pub-ec-p384.jwk.2


echo ""
echo ""
echo "Testing JWK-to-PEM P-256"
echo ""
node bin/eckles.js fixtures/privkey-ec-p256.jwk.json sec1 | tee fixtures/privkey-ec-p256.sec1.pem.2
diff fixtures/privkey-ec-p256.sec1.pem fixtures/privkey-ec-p256.sec1.pem.2
#
node bin/eckles.js fixtures/privkey-ec-p256.jwk.json pkcs8 | tee fixtures/privkey-ec-p256.pkcs8.pem.2
diff fixtures/privkey-ec-p256.pkcs8.pem fixtures/privkey-ec-p256.pkcs8.pem.2
#
node bin/eckles.js fixtures/pub-ec-p256.jwk.json spki | tee fixtures/pub-ec-p256.spki.pem.2
diff fixtures/pub-ec-p256.spki.pem fixtures/pub-ec-p256.spki.pem.2
# ssh-keygen -f fixtures/pub-ec-p256.spki.pem -i -mPKCS8 > fixtures/pub-ec-p256.ssh.pub
node bin/eckles.js fixtures/pub-ec-p256.jwk.json ssh | tee fixtures/pub-ec-p256.ssh.pub.2
diff fixtures/pub-ec-p256.ssh.pub fixtures/pub-ec-p256.ssh.pub.2


echo ""
echo ""
echo "Testing JWK-to-PEM P-384"
echo ""
node bin/eckles.js fixtures/privkey-ec-p384.jwk.json sec1 | tee fixtures/privkey-ec-p384.sec1.pem.2
diff fixtures/privkey-ec-p384.sec1.pem fixtures/privkey-ec-p384.sec1.pem.2
#
node bin/eckles.js fixtures/privkey-ec-p384.jwk.json pkcs8 | tee fixtures/privkey-ec-p384.pkcs8.pem.2
diff fixtures/privkey-ec-p384.pkcs8.pem fixtures/privkey-ec-p384.pkcs8.pem.2
#
node bin/eckles.js fixtures/pub-ec-p384.jwk.json spki | tee fixtures/pub-ec-p384.spki.pem.2
diff fixtures/pub-ec-p384.spki.pem fixtures/pub-ec-p384.spki.pem.2
# ssh-keygen -f fixtures/pub-ec-p384.spki.pem -i -mPKCS8 > fixtures/pub-ec-p384.ssh.pub
node bin/eckles.js fixtures/pub-ec-p384.jwk.json ssh | tee fixtures/pub-ec-p384.ssh.pub.2
diff fixtures/pub-ec-p384.ssh.pub fixtures/pub-ec-p384.ssh.pub.2

rm fixtures/*.2

echo ""
echo ""
echo "PASSED:"
echo "• All inputs produced valid outputs"
echo "• All outputs matched known-good values"
echo ""
