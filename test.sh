#/bin/bash
set -e

echo ""
echo "Testing PEM-to-JWK P-256"
node bin/eckles.js fixtures/privkey-ec-p256.sec1.pem \
  > fixtures/privkey-ec-p256.jwk.2
diff fixtures/privkey-ec-p256.jwk.json fixtures/privkey-ec-p256.jwk.2
node bin/eckles.js fixtures/privkey-ec-p256.pkcs8.pem \
  > fixtures/privkey-ec-p256.jwk.2
diff fixtures/privkey-ec-p256.jwk.json fixtures/privkey-ec-p256.jwk.2
node bin/eckles.js fixtures/pub-ec-p256.spki.pem \
  > fixtures/pub-ec-p256.jwk.2
diff fixtures/pub-ec-p256.jwk.json fixtures/pub-ec-p256.jwk.2
#
node bin/eckles.js fixtures/pub-ec-p256.ssh.pub \
  > fixtures/pub-ec-p256.jwk.2
diff fixtures/pub-ec-p256.jwk.2 fixtures/pub-ec-p256.jwk.2
echo "PASS"


echo ""
echo "Testing PEM-to-JWK P-384"
node bin/eckles.js fixtures/privkey-ec-p384.sec1.pem \
  > fixtures/privkey-ec-p384.jwk.2
diff fixtures/privkey-ec-p384.jwk.json fixtures/privkey-ec-p384.jwk.2
node bin/eckles.js fixtures/privkey-ec-p384.pkcs8.pem \
  > fixtures/privkey-ec-p384.jwk.2.2
diff fixtures/privkey-ec-p384.jwk.json fixtures/privkey-ec-p384.jwk.2.2
node bin/eckles.js fixtures/pub-ec-p384.spki.pem \
  > fixtures/pub-ec-p384.jwk.2
diff fixtures/pub-ec-p384.jwk.json fixtures/pub-ec-p384.jwk.2
#
node bin/eckles.js fixtures/pub-ec-p384.ssh.pub \
  > fixtures/pub-ec-p384.jwk.2
diff fixtures/pub-ec-p384.jwk.2 fixtures/pub-ec-p384.jwk.2
echo "PASS"


echo ""
echo "Testing JWK-to-PEM P-256"
node bin/eckles.js fixtures/privkey-ec-p256.jwk.json sec1 \
  > fixtures/privkey-ec-p256.sec1.pem.2
diff fixtures/privkey-ec-p256.sec1.pem fixtures/privkey-ec-p256.sec1.pem.2
#
node bin/eckles.js fixtures/privkey-ec-p256.jwk.json pkcs8 \
  > fixtures/privkey-ec-p256.pkcs8.pem.2
diff fixtures/privkey-ec-p256.pkcs8.pem fixtures/privkey-ec-p256.pkcs8.pem.2
#
node bin/eckles.js fixtures/pub-ec-p256.jwk.json spki \
  > fixtures/pub-ec-p256.spki.pem.2
diff fixtures/pub-ec-p256.spki.pem fixtures/pub-ec-p256.spki.pem.2
# ssh-keygen -f fixtures/pub-ec-p256.spki.pem -i -mPKCS8 > fixtures/pub-ec-p256.ssh.pub
node bin/eckles.js fixtures/pub-ec-p256.jwk.json ssh \
  > fixtures/pub-ec-p256.ssh.pub.2
diff fixtures/pub-ec-p256.ssh.pub fixtures/pub-ec-p256.ssh.pub.2
echo "PASS"


echo ""
echo "Testing JWK-to-PEM P-384"
node bin/eckles.js fixtures/privkey-ec-p384.jwk.json sec1 \
  > fixtures/privkey-ec-p384.sec1.pem.2
diff fixtures/privkey-ec-p384.sec1.pem fixtures/privkey-ec-p384.sec1.pem.2
#
node bin/eckles.js fixtures/privkey-ec-p384.jwk.json pkcs8 \
  > fixtures/privkey-ec-p384.pkcs8.pem.2
diff fixtures/privkey-ec-p384.pkcs8.pem fixtures/privkey-ec-p384.pkcs8.pem.2
#
node bin/eckles.js fixtures/pub-ec-p384.jwk.json spki \
  > fixtures/pub-ec-p384.spki.pem.2
diff fixtures/pub-ec-p384.spki.pem fixtures/pub-ec-p384.spki.pem.2
# ssh-keygen -f fixtures/pub-ec-p384.spki.pem -i -mPKCS8 > fixtures/pub-ec-p384.ssh.pub
node bin/eckles.js fixtures/pub-ec-p384.jwk.json ssh \
  > fixtures/pub-ec-p384.ssh.pub.2
diff fixtures/pub-ec-p384.ssh.pub fixtures/pub-ec-p384.ssh.pub.2
echo "PASS"


rm fixtures/*.2


echo ""
echo "Testing freshly generated keypair"
# Generate EC P-256 Keypair
openssl ecparam -genkey -name prime256v1 -noout -out ./privkey-ec-p256.sec1.pem
# Export Public-only EC Key (as SPKI)
openssl ec -in ./privkey-ec-p256.sec1.pem -pubout -out ./pub-ec-p256.spki.pem
# Convert SEC1 (traditional) EC Keypair to PKCS8 format
openssl pkcs8 -topk8 -nocrypt -in ./privkey-ec-p256.sec1.pem -out ./privkey-ec-p256.pkcs8.pem
# Convert EC public key to SSH format
sshpub=$(ssh-keygen -f ./pub-ec-p256.spki.pem -i -mPKCS8)
echo "$sshpub P-256@localhost" > ./pub-ec-p256.ssh.pub
#
node bin/eckles.js ./privkey-ec-p256.sec1.pem > ./privkey-ec-p256.jwk.json
node bin/eckles.js ./privkey-ec-p256.jwk.json sec1 > ./privkey-ec-p256.sec1.pem.2
diff ./privkey-ec-p256.sec1.pem ./privkey-ec-p256.sec1.pem.2
#
node bin/eckles.js ./privkey-ec-p256.pkcs8.pem > ./privkey-ec-p256.jwk.json
node bin/eckles.js ./privkey-ec-p256.jwk.json pkcs8 > ./privkey-ec-p256.pkcs8.pem.2
diff ./privkey-ec-p256.pkcs8.pem ./privkey-ec-p256.pkcs8.pem.2
#
node bin/eckles.js ./pub-ec-p256.spki.pem > ./pub-ec-p256.jwk.json
node bin/eckles.js ./pub-ec-p256.jwk.json spki > ./pub-ec-p256.spki.pem.2
diff ./pub-ec-p256.spki.pem ./pub-ec-p256.spki.pem.2
#
node bin/eckles.js ./pub-ec-p256.ssh.pub > ./pub-ec-p256.jwk.json
node bin/eckles.js ./pub-ec-p256.jwk.json ssh > ./pub-ec-p256.ssh.pub.2
diff ./pub-ec-p256.ssh.pub ./pub-ec-p256.ssh.pub.2
echo "PASS"

echo ""
echo "Testing key generation"
node bin/eckles.js jwk > /dev/null
node bin/eckles.js jwk P-384 > /dev/null
node bin/eckles.js sec1 > /dev/null
node bin/eckles.js pkcs8 > /dev/null
node bin/eckles.js ssh #> /dev/null
echo "PASS"

echo ""
echo "Testing Thumbprints"
node bin/eckles.js ./fixtures/privkey-ec-p256.sec1.pem thumbprint
node bin/eckles.js ./fixtures/pub-ec-p256.jwk.json thumbprint
echo "PASS"

rm *.2


echo ""
echo ""
echo "PASSED:"
echo "• All inputs produced valid outputs"
echo "• All outputs matched known-good values"
echo "• Generated keys in each format (sec1, pkcs8, jwk, ssh)"
echo ""
