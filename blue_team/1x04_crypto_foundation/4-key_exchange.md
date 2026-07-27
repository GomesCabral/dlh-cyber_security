# 4. The Key Exchange

## Goal

This laboratory demonstrates how the Diffie-Hellman (DH) key exchange allows two parties to establish the same shared secret over an insecure network without ever transmitting the secret itself. It also explains why certificates are required to prevent man-in-the-middle (MITM) attacks.

---

# Part 1 - The Diffie-Hellman Simulation

## Step 1 - Verify OpenSSL

### Command

```bash
openssl version
```

### Output

```text
OpenSSL 3.6.1 27 Jan 2026 (Library: OpenSSL 3.6.1 27 Jan 2026)
```

---

## Step 2 - Generate Shared Diffie-Hellman Parameters

### Command

```bash
openssl dhparam -out dhparams.pem 2048
```

### Verify the Parameter File

```bash
ls -lh dhparams.pem
```

### Output

```text
-rw-rw-r--. 1 gomes gomes 428 Jul 27 13:22 dhparams.pem
```

### Inspect the Parameters

```bash
openssl dhparam -in dhparams.pem -text -noout | head -n 10
```

### Output

```text
DH Parameters: (2048 bit)
P:
    00:d3:81:10:03:8f:9c:41:79:7d:f6:08:d9:ea:fb:
    77:16:56:62:1e:5e:2f:c9:b7:63:8f:6a:86:3d:57:
    19:34:eb:60:42:e6:fc:5e:ed:cc:3a:ba:93:28:d9:
    58:e5:66:cc:27:70:b1:d7:79:6d:8a:92:b4:b8:8b:
    6a:42:ea:63:6a:4a:c2:54:57:dc:16:ce:eb:8b:c8:
    94:02:e0:e1:49:66:df:62:2a:e4:09:fd:0c:a7:ae:
    79:a9:c3:d3:29:db:3a:b6:5b:63:fd:fc:83:dd:fa:
    07:05:ed:ba:22:62:bc:7c:59:d7:78:f4:89:52:24:
```

### Analysis

The `dhparams.pem` file contains the public Diffie-Hellman parameters shared between Alice and Bob. These values include a large prime number and a generator. They are public information and may be transmitted over an insecure network without affecting security.

---

## Step 3 - Generate Alice's Private Key

### Command

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out alice_private.pem
```

Protect the private key:

```bash
chmod 600 alice_private.pem
```

Verify:

```bash
ls -l alice_private.pem
```

### Output

```text
-rw-------. 1 gomes gomes 806 Jul 27 13:22 alice_private.pem
```

### Analysis

Alice's private key is secret and must never leave her computer. Only Alice knows this value.

---

## Step 4 - Generate Alice's Public Key

### Command

```bash
openssl pkey \
  -in alice_private.pem \
  -pubout \
  -out alice_public.pem
```

Verify:

```bash
ls -lh alice_public.pem
```

### Output

```text
-rw-rw-r--. 1 gomes gomes 800 Jul 27 13:23 alice_public.pem
```

### Analysis

Alice's public key is derived from her private key and the shared DH parameters. This key can safely be transmitted over the network.

---

## Step 5 - Generate Bob's Private Key

### Command

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out bob_private.pem
```

Protect the private key:

```bash
chmod 600 bob_private.pem
```

Verify:

```bash
ls -l bob_private.pem
```

### Output

```text
-rw-------. 1 gomes gomes 806 Jul 27 13:25 bob_private.pem
```

### Analysis

Bob independently generates his own private key. It is different from Alice's private key and must remain secret.

---

## Step 6 - Generate Bob's Public Key

### Command

```bash
openssl pkey \
  -in bob_private.pem \
  -pubout \
  -out bob_public.pem
```

Verify:

```bash
ls -lh bob_public.pem
```

### Output

```text
-rw-rw-r--. 1 gomes gomes 804 Jul 27 13:25 bob_public.pem
```

### Analysis

Bob's public key is safe to exchange over the network. Knowing Bob's public key does not reveal his private key.

---

## Step 7 - Derive Alice's Shared Secret

### Command

```bash
openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin
```

Verify:

```bash
ls -lh alice_secret.bin
```

### Output

```text
-rw-rw-r--. 1 gomes gomes 256 Jul 27 13:27 alice_secret.bin
```

Generate a SHA-256 fingerprint:

```bash
sha256sum alice_secret.bin
```

### Output

```text
4a50223254b5abc8f7aaddb23ea4873eed7e72894a05a5ace9d4293e9c1ed525  alice_secret.bin
```

### Analysis

Alice combined her private key with Bob's public key to derive the shared secret. The secret itself was never transmitted over the network.

---

## Step 8 - Derive Bob's Shared Secret

### Command

```bash
openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin
```

Generate a SHA-256 fingerprint:

```bash
sha256sum bob_secret.bin
```

### Output

```text
4a50223254b5abc8f7aaddb23ea4873eed7e72894a05a5ace9d4293e9c1ed525  bob_secret.bin
```

### Analysis

Bob combined his private key with Alice's public key and independently produced the same shared secret.

---

## Step 9 - Compare the Shared Secrets

### Command

```bash
diff alice_secret.bin bob_secret.bin
echo $?
```

### Output

```text
0
```

### Second Verification

```bash
cmp alice_secret.bin bob_secret.bin
echo $?
```

### Output

```text
0
```

### SHA-256 Comparison

```bash
sha256sum alice_secret.bin bob_secret.bin
```

### Output

```text
4a50223254b5abc8f7aaddb23ea4873eed7e72894a05a5ace9d4293e9c1ed525  alice_secret.bin
4a50223254b5abc8f7aaddb23ea4873eed7e72894a05a5ace9d4293e9c1ed525  bob_secret.bin
```

### Analysis

The `diff` and `cmp` commands both returned exit code `0`, confirming that the two binary files are identical. The identical SHA-256 hashes further prove that Alice and Bob independently generated the exact same shared secret.

---

## Step 10 - Inspect the Shared Secret

### Command

```bash
xxd -l 32 alice_secret.bin
```

### Output

```text
00000000: 20df 5588 c41f 041d 117b 9f29 a309 e982   .U......{.)....
00000010: 7b98 5563 aafe a769 f67a 2292 ca10 45d0  {.Uc...i.z"...E.
```

### Command

```bash
xxd -l 32 bob_secret.bin
```

### Output

```text
00000000: 20df 5588 c41f 041d 117b 9f29 a309 e982   .U......{.)....
00000010: 7b98 5563 aafe a769 f67a 2292 ca10 45d0  {.Uc...i.z"...E.
```

### Analysis

The first 32 bytes of both files are identical, providing additional confirmation that both participants derived the same shared secret.

---

# Part 2 - Explanation

Imagine Alice and Bob want to agree on a secret password while someone is listening to every message they exchange. Instead of sending the password, they each create a private secret that never leaves their computer and exchange only public information. Using Diffie-Hellman mathematics, Alice combines her private key with Bob's public key, while Bob combines his private key with Alice's public key. Although they perform different calculations, both arrive at the exact same shared secret. An eavesdropper (Eve) can see the public parameters and the exchanged public keys but cannot calculate the shared secret because she does not know either private key. This allows Alice and Bob to establish an encrypted communication channel without ever transmitting the encryption key itself.

---

# Part 3 - Man-in-the-Middle (MITM) Attack

Diffie-Hellman by itself does not authenticate the participants. An attacker named Eve can intercept Alice's public key and replace it with her own public key before sending it to Bob. She performs the same attack in the opposite direction, replacing Bob's public key before it reaches Alice. Alice establishes one shared secret with Eve, while Bob establishes a different shared secret with Eve. Eve can decrypt every message, read or modify it, encrypt it again using the second secret, and forward it to the other party without either side realizing they are communicating through an attacker.

---

# MedDefense Scenario

If the VPN tunnel between the Central site and the Westside clinic used Diffie-Hellman without certificate-based authentication, an attacker positioned between the two sites could impersonate each endpoint. The attacker would establish two encrypted VPN tunnels: one with Central and another with Westside. All patient records, billing data, Active Directory authentication traffic, and administrative communications could be intercepted, modified, and re-encrypted. Strong AES encryption alone would not prevent this attack because the attacker would possess both shared secrets.

Certificates prevent this attack by binding a trusted identity to each public key. During the VPN handshake, each endpoint verifies that the certificate was issued by a trusted Certificate Authority and that the digital signature matches the corresponding private key. Since Eve cannot produce a valid certificate or digital signature for a legitimate MedDefense VPN endpoint, the connection is rejected before the encrypted tunnel is established.

---

# Why Certificates Are Required

Diffie-Hellman solves one problem:

```text
How can two parties agree on the same secret without sending it?
```

Certificates solve another problem:

```text
How can each party verify the identity of the owner of the public key?
```

Modern secure protocols combine:

- Diffie-Hellman (DH or ECDHE) for key exchange.
- X.509 certificates for authentication.
- Digital signatures for identity verification.
- AES-GCM or ChaCha20-Poly1305 for encrypting the session.

---

# Commands Summary

```bash
openssl version

openssl dhparam -out dhparams.pem 2048

openssl genpkey -paramfile dhparams.pem -out alice_private.pem
chmod 600 alice_private.pem
openssl pkey -in alice_private.pem -pubout -out alice_public.pem

openssl genpkey -paramfile dhparams.pem -out bob_private.pem
chmod 600 bob_private.pem
openssl pkey -in bob_private.pem -pubout -out bob_public.pem

openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin

openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin

diff alice_secret.bin bob_secret.bin
cmp alice_secret.bin bob_secret.bin

sha256sum alice_secret.bin bob_secret.bin

xxd -l 32 alice_secret.bin
xxd -l 32 bob_secret.bin
```

---

# Conclusion

This laboratory successfully demonstrated a complete Diffie-Hellman key exchange using OpenSSL. Alice and Bob generated independent private keys, exchanged only public keys, and derived identical shared secrets without transmitting the secret itself. The matching SHA-256 hashes, identical binary files, and zero exit codes from both `diff` and `cmp` confirm that the exchange was successful. The laboratory also demonstrated that Diffie-Hellman alone is insufficient against man-in-the-middle attacks, highlighting why certificate-based authentication is essential for protecting MedDefense's VPN infrastructure and other secure communications.
