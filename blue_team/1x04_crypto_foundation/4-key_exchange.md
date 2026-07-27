cd ~/dlh-cyber_security/blue_team/1x04_crypto_foundation

echo "=== OPENSSL VERSION ==="
openssl version

echo
echo "=== GENERATE DH PARAMETERS ==="
time openssl dhparam -out dhparams.pem 2048

echo
echo "=== DH PARAMETER FILE ==="
ls -lh dhparams.pem
openssl dhparam -in dhparams.pem -text -noout | head -n 5

echo
echo "=== ALICE KEY PAIR ==="
openssl genpkey -paramfile dhparams.pem -out alice_private.pem
chmod 600 alice_private.pem
openssl pkey -in alice_private.pem -pubout -out alice_public.pem
ls -l alice_private.pem alice_public.pem

echo
echo "=== BOB KEY PAIR ==="
openssl genpkey -paramfile dhparams.pem -out bob_private.pem
chmod 600 bob_private.pem
openssl pkey -in bob_private.pem -pubout -out bob_public.pem
ls -l bob_private.pem bob_public.pem

echo
echo "=== DERIVE ALICE SECRET ==="
openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin

ls -lh alice_secret.bin
sha256sum alice_secret.bin

echo
echo "=== DERIVE BOB SECRET ==="
openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin

ls -lh bob_secret.bin
sha256sum bob_secret.bin

echo
echo "=== COMPARE SECRETS ==="
diff alice_secret.bin bob_secret.bin
echo "diff exit code: $?"

cmp alice_secret.bin bob_secret.bin
echo "cmp exit code: $?"

echo
echo "=== SECRET HASHES ==="
sha256sum alice_secret.bin bob_secret.bin
