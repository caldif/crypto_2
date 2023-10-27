1. don't need n or pn because you don't have to handle out of order messages
2. every time alice sends a message, symmetric ratchet happens
3. when sender changes, alice v bob, new diffie hellman key 
4. receive certificates 
5. service public key is given in parameters
6. need to have a number of old keys stored
7. root key, send key, receieve key, DH key, server verification key, and one more 

**When HEADER changes, you make a new DH**
- Every message from either party begins with a header which contains the sender's current ratchet public key. When a new ratchet public key is received from the remote party, a DH ratchet step is performed which replaces the local party's current ratchet key pair with a new key pair.


**DISCARD OLD KEYS WHEN A RATCHET OCCURS**

self.conns is to store lists of conversations
- store conversations by storing their respective keys
- we make a server and they are the certificate authority

- we manage crypto for server
- we don't need to store our certificate but we are storing everyone we can talk to's certificate

**Abuse Report**
- encrypt the name of the sender and the message under the **messaging server's** public key, send it to the server
**Encryption**
- Message headers should be authenticated

**Decryption**
- Performs a symmetric-key ratchet step to derive the relevant message key and next chain key, and decrypts the message.
- Message headers should be authenticated

**Libraries**
- pickle
- cryptography

**Function Usage Recommendations**

GENERATE_DH(): This function is recommended to generate a key pair based on the Curve25519 or Curve448 elliptic curves [7].

DH(dh_pair, dh_pub): This function is recommended to return the output from the X25519 or X448 function as defined in [7]. There is no need to check for invalid public keys.

KDF_RK(rk, dh_out): This function is recommended to be implemented using HKDF [3] with SHA-256 or SHA-512 [8], using rk as HKDF salt, dh_out as HKDF input key material, and an application-specific byte sequence as HKDF info. The info value should be chosen to be distinct from other uses of HKDF in the application.

KDF_CK(ck): HMAC [2] with SHA-256 or SHA-512 [8] is recommended, using ck as the HMAC key and using separate constants as input (e.g. a single byte 0x01 as input to produce the message key, and a single byte 0x02 as input to produce the next chain key).

ENCRYPT(mk, plaintext, associated_data): This function is recommended to be implemented with an AEAD encryption scheme based on either SIV or a composition of CBC with HMAC [5], [9]. These schemes provide some misuse-resistance in case a key is mistakenly used multiple times. A concrete recommendation based on CBC and HMAC is as follows:

HKDF is used with SHA-256 or SHA-512 to generate 80 bytes of output. The HKDF salt is set to a zero-filled byte sequence equal to the hash's output length. HKDF input key material is set to mk. HKDF info is set to an application-specific byte sequence distinct from other uses of HKDF in the application.

The HKDF output is divided into a 32-byte encryption key, a 32-byte authentication key, and a 16-byte IV.

The plaintext is encrypted using AES-256 in CBC mode with PKCS#7 padding, using the encryption key and IV from the previous step [10], [11].

HMAC is calculated using the authentication key and the same hash function as above [2]. The HMAC input is the associated_data prepended to the ciphertext. The HMAC output is appended to the ciphertext.

