[![http://hackingyseguridad.com/](https://github.com/hackingyseguridad/ia/raw/main/banner.png)](https://github.com/hackingyseguridad/ia/blob/main/banner.png)

---

### 1.- Protocolos y [cifrados recomendados](https://github.com/hackingyseguridad/cifrados/blob/main/LEEME.md):

[#1--protocolos-y-cifrados-recomendados](#1--protocolos-y-cifrados-recomendados)

| Protocolo                             | Seguridad Media (Recomendado)                            | Seguridad Alta (Recomendado)                              |
| ------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------- |
| **Protocolos TLS**                    | TLS 1.2 (solo ECDHE + AEAD), TLS 1.3                     | TLS 1.3                                                   |
| **Cifrado de transporte (TLS/SSH)**   | AES-128-GCM, CHACHA20-POLY1305                           | AES-256-GCM, CHACHA20-POLY1305                            |
| **Intercambio de claves (TLS/IPsec)** | ECDHE (X25519, P-256, P-384), DH grupo 14 (2048 bits)    | ECDHE (P-384, P-521, X25519), DH grupo 21 (curva P-521)   |
| **Funciones hash (HMAC)**             | SHA-2 (256, 384 bits)                                    | SHA-2 (512 bits), SHA-3                                   |
| **Firma digital**                     | ECDSA (P-256), RSA (≥3072 bits)                          | EdDSA (Ed25519), ECDSA (P-384), RSA (4096 bits)           |
| **IPsec IKEv2**                       | AES-256-GCM, SHA-2, DH grupo 19 (curva P-256)            | AES-256-GCM, SHA-384/512, DH grupo 20 (P-384) o 21 (P-521) + ML-KEM (RFC 9370, híbrido) |
| **SSH v2**                            | curve25519-sha256, aes256-gcm@openssh.com o aes256-ctr, hmac-sha2-256-etm@openssh.com (OpenSSH ≥ 10.6 recomendado) | mlkem768x25519-sha256, ssh-ed25519, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com (OpenSSH ≥ 10.6 recomendado) |
| **WiFi**                              | WPA2-AES/CCMP (con PMF 802.11w), WPA3-SAE                | WPA3-Enterprise modo 192 bits (GCMP-256, P-384, SHA-384)  |
| **PGP/GPG**                           | AES-192, ECDH (Curve25519), ECDSA                        | AES-256, EdDSA (Ed25519), RSA 4096, OpenPGP v6 (RFC 9580) |
| **Post-cuántico (PQC)**               | X25519MLKEM768 (híbrido), ML-KEM-768 (Kyber), ML-DSA-65 (Dilithium) | ML-KEM-1024 (híbrido con ECDH P-384), ML-DSA-87, SLH-DSA (SPHINCS+), FN-DSA (Falcon), LMS/XMSS (firmware) |
| **Contraseñas / KDF**                 | PBKDF2-HMAC-SHA256 (≥600.000 iteraciones), bcrypt (coste ≥12) | Argon2id, scrypt                                     |
| **Cifrado en reposo**                 | AES-256-XTS (disco), AES-256-GCM                         | AES-256-GCM-SIV, XChaCha20-Poly1305 (nonce nunca repetido) |
| **Cifrado asimétrico**                | RSA-OAEP (≥3072 bits)                                    | HPKE (RFC 9180) con X25519 o P-384                        |

---

### 2.- Cifrados y protocolos no recomendados (Obsoletos rotos o vulnerables):

[#2--cifrados-y-protocolos-no-recomendados-obsoletos-rotos-o-vulnerables](#2--cifrados-y-protocolos-no-recomendados-obsoletos-rotos-o-vulnerables)

| Tipo / Protocolo                  | algoritmos / cifrados a evitar (Inseguros)                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| **Protocolos SSL/TLS obsoletos**  | SSLv2, SSLv3, TLS 1.0, TLS 1.1                                                             |
| **Cifrados de bloque débiles**    | DES (40/56 bits), 3DES, RC2, RC4, IDEA, CAST5, Blowfish, suites NULL / EXPORT / anónimas (aNULL, eNULL) |
| **Modos de operación inseguros**  | AES-ECB, AES-CBC (sin Encrypt-then-MAC), AES-CFB, AES-CTR sin MAC (cualquier modo sin autenticación)    |
| **Intercambio de clave inseguro** | RSA estático (sin PFS; ROBOT, Marvin), DH/ECDH estático, PSK sin (EC)DHE, grupos DH < 2048 bits, curvas < 224 bits |
| **Funciones hash rotas**          | MD2, MD4, MD5, SHA-1 (en firmas y certificados; HMAC-SHA1 es solo obsoleto)                |
| **Firma digital débil**           | RSA < 2048 bits, DSA, ECDSA con curvas < 224 bits o no estándar, ssh-rsa (SHA-1; usar rsa-sha2-256/512), RSASHA1 (DNSSEC) |
| **IPsec**                         | IKEv1 (modo agresivo), grupos DH 1, 2 y 5, 3DES, MD5/SHA-1                                 |
| **SSH**                           | SSH v1; cifrados: 3des-cbc, arcfour, blowfish-cbc, aes*-cbc; MACs: hmac-md5, hmac-sha1 (obsoletos); claves ssh-rsa (SHA-1), ssh-dss; OpenSSH < 9.6 (Terrapin) |
| **WiFi**                          | WEP, WPA-TKIP, WPA2 con TKIP, WPS activado, WPA3 en modo transición o sin PMF              |
| **PGP/GPG**                       | RSA < 3072 bits, DSA, ElGamal, IDEA, CAST5, 3DES, SHA-1, mensajes sin MDC/AEAD (EFAIL)     |
| **Almacenamiento**                | MD5, SHA-1, SHA-256 sin sal/KDF para contraseñas, DES, 3DES, ECB, AES-128 (en contextos de alta seguridad) |
| **No rotos, pero no recomendados (compatibilidad)** | CAMELLIA, ARIA, Twofish, Serpent: válidos, pero poco soportados; preferir AES o ChaCha20 |

Vulnerabilidades conocidas asociadas: POODLE, BEAST, CRIME, Lucky13, Sweet32 (3DES), KRACK (WPA2), Dragonblood (WPA3), FragAttacks (WiFi), Logjam, FREAK, DROWN, SLOTH, Heartbleed, ROBOT y Marvin (RSA PKCS#1 v1.5), Raccoon (DH), Terrapin (SSH), EFAIL (PGP), BlastRADIUS (RADIUS/MD5), SHAttered (SHA-1), ataques a CBC (padding oracle, bit flipping)

[**+ cifrados recomendados**](https://github.com/hackingyseguridad/cifrados/blob/main/LEEME.md)

[**+ cifrados recomendados 2**](https://github.com/hackingyseguridad/cifrados/blob/main/CIFRADOS.md)

---

### 3.- Certificado digital, recomendaciones de seguridad

[#3--certificado-digital-recomendaciones-de-seguridad](#3--certificado-digital-recomendaciones-de-seguridad)

<https://github.com/hackingyseguridad/certificado/>

---

### 4.- Escaneo subrutinas:

[#4--escaneo-subrutinas](#4--escaneo-subrutinas)

testssl.sh IP/rango

sh scan_cifrados.sh lista de IP en ip.txt

nmap --script ssl-enum-ciphers -p 443 IP

ssh-audit IP

---

<http://www.hackingyseguridad.com/>
