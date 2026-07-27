# 4. The Key Exchange

## Goal

This laboratory simulates a Diffie-Hellman key exchange between Alice and Bob using OpenSSL. It demonstrates how two parties can derive the same shared secret over an insecure network without transmitting that secret directly. It also explains why unauthenticated Diffie-Hellman is vulnerable to a man-in-the-middle attack and why certificates are required.

> **Evidence requirement:** Replace every `[PASTE YOUR OUTPUT HERE]` placeholder with the exact output from your own terminal. Do not invent command outputs.

---

# Part 1 - The Diffie-Hellman Simulation

## 1. Verify the OpenSSL Version

Command:

```bash
openssl version
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

---

## 2. Generate Shared Diffie-Hellman Parameters

Alice and Bob must use the same Diffie-Hellman parameter set.

Command:

```bash
openssl dhparam -out dhparams.pem 2048
```

This command may take several minutes because OpenSSL must generate a safe 2048-bit prime number.

The terminal may display dots, plus signs, and asterisks while generating the parameters.

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Verify that the file was created:

```bash
ls -lh dhparams.pem
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Inspect the parameters:

```bash
openssl dhparam \
  -in dhparams.pem \
  -text \
  -noout
```

Output:

```text
[PASTE THE FIRST RELEVANT LINES HERE]
```

### Explanation

The `dhparams.pem` file contains the public mathematical parameters used by both Alice and Bob.

These parameters mainly include:

- a large prime number;
- a generator.

The parameters are not secret. Alice, Bob, and anyone listening on the network may know them.

---

## 3. Generate Alice's Private Key

Command:

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out alice_private.pem
```

The command may complete without displaying output.

Protect Alice's private key:

```bash
chmod 600 alice_private.pem
```

Verify the file and permissions:

```bash
ls -l alice_private.pem
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

Alice's private key contains her secret Diffie-Hellman value.

It must never be:

- transmitted over the network;
- shared with Bob;
- committed to GitHub;
- exposed to another user.

The `600` permissions allow only the file owner to read and modify the private key.

---

## 4. Extract Alice's Public Key

Command:

```bash
openssl pkey \
  -in alice_private.pem \
  -pubout \
  -out alice_public.pem
```

Verify the public key:

```bash
ls -lh alice_public.pem
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Inspect the public key:

```bash
openssl pkey \
  -pubin \
  -in alice_public.pem \
  -text \
  -noout
```

Output:

```text
[PASTE THE FIRST RELEVANT LINES HERE]
```

### Explanation

Alice's public key is mathematically derived from:

- her private key;
- the shared DH parameters.

Alice can send this public key to Bob over an insecure network.

The public key does not reveal Alice's private key.

---

## 5. Generate Bob's Private Key

Command:

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out bob_private.pem
```

Protect Bob's private key:

```bash
chmod 600 bob_private.pem
```

Verify the file:

```bash
ls -l bob_private.pem
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

Bob generates his own private value independently from Alice.

Alice and Bob must have:

- the same DH parameters;
- different private keys;
- different public keys.

---

## 6. Extract Bob's Public Key

Command:

```bash
openssl pkey \
  -in bob_private.pem \
  -pubout \
  -out bob_public.pem
```

Verify the file:

```bash
ls -lh bob_public.pem
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Inspect Bob's public key:

```bash
openssl pkey \
  -pubin \
  -in bob_public.pem \
  -text \
  -noout
```

Output:

```text
[PASTE THE FIRST RELEVANT LINES HERE]
```

---

## 7. Derive the Shared Secret from Alice's Side

Alice combines:

- her own private key;
- Bob's public key.

Command:

```bash
openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin
```

Verify the generated secret file:

```bash
ls -lh alice_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Calculate a SHA-256 fingerprint of the secret:

```bash
sha256sum alice_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

Alice uses Bob's public key together with her private key to derive a shared secret.

The secret itself is never transmitted.

---

## 8. Derive the Shared Secret from Bob's Side

Bob combines:

- his own private key;
- Alice's public key.

Command:

```bash
openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin
```

Verify the generated secret file:

```bash
ls -lh bob_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Calculate its SHA-256 fingerprint:

```bash
sha256sum bob_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The SHA-256 fingerprint should be identical to the fingerprint of `alice_secret.bin`.

---

## 9. Compare the Two Shared Secrets

Command:

```bash
diff alice_secret.bin bob_secret.bin
```

Expected result:

```text
No output
```

When `diff` produces no output, both files are identical.

Check the exit code:

```bash
echo $?
```

Expected output:

```text
0
```

A zero exit code confirms that the files match.

Perform an additional comparison:

```bash
cmp alice_secret.bin bob_secret.bin
```

Check the result:

```bash
echo $?
```

Expected output:

```text
0
```

Document the actual result:

```text
[PASTE YOUR OUTPUT HERE]
```

---

## 10. Compare the Secret Fingerprints

Command:

```bash
sha256sum alice_secret.bin bob_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The two hashes must be identical.

Example format:

```text
same_hash_value  alice_secret.bin
same_hash_value  bob_secret.bin
```

---

## 11. Optional Binary Inspection

For laboratory verification only, display the first 32 bytes of each secret:

```bash
xxd -l 32 alice_secret.bin
```

```bash
xxd -l 32 bob_secret.bin
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The displayed bytes should match.

Do not publish or commit the complete shared secret.

---

# Part 2 - Explanation for a Non-Cryptographer

Alice and Bob first agreed on public mathematical values that anyone, including an eavesdropper, could see. Each person then created a private value that never left their own computer and a related public value that could safely be exchanged. Alice combined her private value with Bob's public value, while Bob combined his private value with Alice's public value. The Diffie-Hellman mathematics caused both calculations to produce the same shared secret, even though that secret was never transmitted across the network. Eve could observe the public parameters and both public keys, but she would not possess either private value. With strong parameters, calculating the shared secret from public information alone is computationally impractical.

---

# How the Mathematics Works

The process can be represented conceptually as follows:

```text
Public DH parameters:
Prime number p
Generator g
```

Alice creates:

```text
Alice private value = a
Alice public value = g^a mod p
```

Bob creates:

```text
Bob private value = b
Bob public value = g^b mod p
```

Alice calculates:

```text
Bob public value raised to Alice's private value
(g^b)^a mod p
=
g^(ab) mod p
```

Bob calculates:

```text
Alice public value raised to Bob's private value
(g^a)^b mod p
=
g^(ab) mod p
```

Both sides therefore calculate:

```text
g^(ab) mod p
```

This is why Alice and Bob derive the same secret.

---

# What Eve Can See

An eavesdropper may observe:

- the DH parameters;
- Alice's public key;
- Bob's public key;
- the encrypted network traffic.

Eve does not know:

- Alice's private key;
- Bob's private key;
- the resulting shared secret.

Recovering the private values from the public values requires solving the discrete logarithm problem, which is computationally impractical when strong parameters are used.

---

# Part 3 - The Man-in-the-Middle Attack

Plain Diffie-Hellman establishes a shared secret but does not authenticate the identity of the other participant. Eve can intercept Alice's public key and replace it with a public key controlled by Eve, then intercept Bob's public key and replace it with another Eve-controlled key. Alice therefore derives one shared secret with Eve, while Bob derives a different shared secret with Eve. Eve can decrypt Alice's messages, read or modify them, encrypt them again using the secret shared with Bob, and forward them without either side immediately noticing. The attack succeeds because Alice and Bob have no trusted proof that the public keys they received belong to each other.

---

# Man-in-the-Middle Attack Flow

Normal exchange:

```text
Alice <--------------------------> Bob

Alice private + Bob public
              =
Shared Secret

Bob private + Alice public
              =
Same Shared Secret
```

Attack exchange:

```text
Alice <----------> Eve <----------> Bob
```

Eve creates two separate exchanges:

```text
Alice + Eve = Shared Secret 1
Eve + Bob   = Shared Secret 2
```

Traffic flow:

```text
Alice encrypts with Secret 1
            |
            v
Eve decrypts with Secret 1
Eve reads or modifies the message
Eve encrypts with Secret 2
            |
            v
Bob decrypts with Secret 2
```

The communication appears encrypted, but Eve can access everything.

---

# MedDefense VPN Scenario

If the VPN tunnel between the MedDefense Central site and Westside used Diffie-Hellman without certificate-based authentication or another trusted authentication mechanism, an attacker positioned on the network path could impersonate each VPN endpoint to the other.

The attacker could establish:

```text
one encrypted tunnel with Central
```

and:

```text
another encrypted tunnel with Westside
```

The attacker could then silently relay, inspect, and modify:

- patient information;
- billing traffic;
- Active Directory authentication;
- administrative commands;
- backup traffic;
- medical device communications.

Strong AES encryption would not prevent this attack because the attacker would participate as a valid endpoint in both attacker-controlled encrypted sessions.

---

# How Certificates Prevent the Attack

Certificates bind an identity to a public key.

For example:

```text
Identity:
vpn-westside.meddefense.local
```

is linked to:

```text
Westside VPN public key
```

by a certificate signed by a trusted Certificate Authority.

During an authenticated exchange, the VPN endpoint:

1. receives the peer's certificate;
2. verifies the CA signature;
3. checks the certificate identity;
4. checks the expiration date;
5. checks revocation status;
6. verifies that the peer possesses the matching private key;
7. verifies the signature over the key-exchange data.

Eve may create her own DH public key, but she cannot:

- produce a valid certificate for the MedDefense VPN identity;
- sign the handshake using the legitimate private key;
- build a trusted certificate chain.

The VPN therefore rejects the attacker.

---

# Why Certificates Are Necessary

Diffie-Hellman answers:

```text
How can two parties derive the same secret without transmitting it?
```

Certificates answer:

```text
How can each party verify the identity of the public-key owner?
```

A secure authenticated key exchange combines:

1. Diffie-Hellman or ECDHE for key agreement;
2. an X.509 certificate for identity;
3. a digital signature for proof of private-key possession;
4. a trusted Certificate Authority;
5. symmetric encryption for the session data.

---

# Shared Secret Versus Session Keys

The raw Diffie-Hellman secret should not normally be used directly as an AES key.

Real protocols pass the shared secret through a **Key Derivation Function (KDF)**.

Conceptually:

```text
Diffie-Hellman Shared Secret
              |
              v
     Key Derivation Function
              |
              +--> Client encryption key
              |
              +--> Server encryption key
              |
              +--> Client IV
              |
              +--> Server IV
              |
              +--> Additional integrity values
```

The KDF combines the shared secret with other handshake values such as:

- random nonces;
- transcript hashes;
- protocol labels;
- session context.

This ensures that separate keys are produced for separate cryptographic purposes.

---

# Forward Secrecy

Modern protocols normally use temporary Diffie-Hellman keys.

This is called:

```text
DHE
```

or:

```text
ECDHE
```

The letter `E` means:

```text
Ephemeral
```

A new temporary key pair is generated for each session.

If an attacker later steals the server's long-term certificate private key, previously recorded sessions should remain protected because their temporary DH private values no longer exist.

This property is called:

```text
Forward Secrecy
```

---

# Traditional DH Versus ECDHE

| Feature | Traditional DH | ECDHE |
|---|---|---|
| Mathematical basis | Finite-field discrete logarithm | Elliptic-curve discrete logarithm |
| Key size | Larger | Smaller |
| Performance | Higher overhead | More efficient |
| Modern TLS use | Less common | Common |
| Forward secrecy | Yes when ephemeral | Yes |
| Suitable for constrained devices | Less suitable | More suitable |

ECDHE is generally more suitable for MedDefense medical devices because it provides strong security with lower computational and bandwidth requirements.

---

# MedDefense Security Recommendations

MedDefense should apply the following controls:

1. Use authenticated IKEv2 for site-to-site VPN tunnels.
2. Authenticate VPN endpoints using certificates issued by a trusted enterprise Certificate Authority.
3. Prefer ephemeral Diffie-Hellman or ECDHE to provide forward secrecy.
4. Protect VPN private keys with strict filesystem permissions or hardware-backed key storage.
5. Validate certificate identity, trust chain, expiration date, revocation status, and key usage.
6. Replace the Westside consumer router with the approved enterprise firewall.
7. Monitor failed certificate validation, unexpected peer identities, and repeated tunnel renegotiations.
8. Rotate VPN certificates and private keys according to the MedDefense cryptographic policy.
9. Disable weak or obsolete DH groups.
10. Use current vendor-recommended IKE and IPsec cryptographic suites.

---

# Connection to the Existing VPN Configuration

The MedDefense audit notes state that the site-to-site VPN currently uses:

```text
Encryption: AES-256
Integrity: SHA-256
Key Exchange: IKEv2
DH Group: 14
```

These cryptographic choices provide protection for data in transit.

However, the overall security also depends on:

- how each endpoint is authenticated;
- how the private keys are protected;
- whether certificates are validated correctly;
- whether the Westside router firmware is secure;
- whether weak fallback configurations are permitted.

A strong algorithm cannot compensate for an unauthenticated or compromised endpoint.

---

# Production Guidance

The command below generates custom 2048-bit DH parameters:

```bash
openssl dhparam -out dhparams.pem 2048
```

This is useful for understanding the process in a laboratory.

In production, MedDefense should follow the configuration guidance of the VPN or TLS vendor. Modern systems often use reviewed standard groups rather than generating custom parameters.

Common modern alternatives include:

- standard finite-field DH groups;
- P-256;
- P-384;
- X25519.

X25519 is widely used in modern TLS because it provides strong security, good performance, and simpler implementation properties.

---

# Commands Summary

## OpenSSL Version

```bash
openssl version
```

## Generate Shared DH Parameters

```bash
openssl dhparam -out dhparams.pem 2048
```

## Inspect Parameters

```bash
openssl dhparam \
  -in dhparams.pem \
  -text \
  -noout
```

## Generate Alice's Key Pair

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out alice_private.pem
```

```bash
chmod 600 alice_private.pem
```

```bash
openssl pkey \
  -in alice_private.pem \
  -pubout \
  -out alice_public.pem
```

## Generate Bob's Key Pair

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out bob_private.pem
```

```bash
chmod 600 bob_private.pem
```

```bash
openssl pkey \
  -in bob_private.pem \
  -pubout \
  -out bob_public.pem
```

## Alice Derives the Secret

```bash
openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin
```

## Bob Derives the Secret

```bash
openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin
```

## Compare the Secrets

```bash
diff alice_secret.bin bob_secret.bin
```

```bash
echo $?
```

```bash
cmp alice_secret.bin bob_secret.bin
```

```bash
echo $?
```

## Compare SHA-256 Fingerprints

```bash
sha256sum alice_secret.bin bob_secret.bin
```

## Inspect the First Bytes

```bash
xxd -l 32 alice_secret.bin
```

```bash
xxd -l 32 bob_secret.bin
```

---

# Expected Laboratory Result

The laboratory is successful when:

- `dhparams.pem` is created successfully;
- Alice and Bob have different private keys;
- Alice and Bob have different public keys;
- only the public keys are exchanged;
- `alice_secret.bin` and `bob_secret.bin` are generated;
- both files have the same SHA-256 hash;
- `diff alice_secret.bin bob_secret.bin` displays no output;
- the `diff` exit code is `0`;
- the `cmp` exit code is `0`.

---

# Security Conclusions

This laboratory demonstrates that Diffie-Hellman solves the symmetric-key distribution problem. Alice and Bob can derive an identical secret without transmitting the secret itself across the network.

A passive attacker can observe:

- the DH parameters;
- Alice's public key;
- Bob's public key.

However, the attacker cannot practically calculate the secret without obtaining one of the private keys.

The laboratory also demonstrates an important limitation: Diffie-Hellman alone does not authenticate either participant. An active attacker can replace the public keys and establish separate shared secrets with Alice and Bob.

MedDefense must therefore use authenticated key exchange by combining:

- DH or ECDHE;
- trusted X.509 certificates;
- digital signatures;
- secure private-key storage;
- modern symmetric encryption.

This combination protects the Central-to-Westside VPN and other sensitive MedDefense communications from passive interception and man-in-the-middle attacks.
