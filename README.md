
### 1.- Cifrados recomendados:

| Protocolo | Seguridad Media (Recomendado) | Seguridad Alta (Recomendado) |
| :--- | :--- | :--- |
| **Protocolos TLS** | TLS 1.2, TLS 1.3, TLS 1.4 (futuro) | TLS 1.3, TLS 1.4 |
| **Cifrado de transporte (TLS/SSH)** | AES-128-GCM, AES-192-GCM, CHACHA20-POLY1305 | AES-256-GCM, CHACHA20-POLY1305 |
| **Intercambio de claves (TLS/IPsec)** | ECDHE (curvas P-256, P-384), DH con grupo 14 (2048 bits) | ECDHE (curvas P-384, P-521), DH grupo 21 (curva 512 bits) |
| **Funciones hash (HMAC)** | SHA-2 (256, 384 bits) | SHA-2 (512 bits), SHA-3 |
| **Firma digital** | ECDSA (P-256), RSA (≥3072 bits) | EdDSA (Ed25519), ECDSA (P-384), RSA (4096 bits) |
| **IPsec IKEv2** | AES-256, SHA-2, DH grupo 19 (256 bits curva) | AES-256, SHA-512, DH grupo 21 (512 bits curva) |
| **SSH v2** | curve25519-sha256, aes256-ctr, hmac-sha2-256 | ssh-ed25519, aes256-gcm, chacha20-poly1305 |
| **WiFi** | WPA2-AES (con mitigaciones), WPA3-SAE | WPA3-Enterprise (AES-192/256) |
| **PGP/GPG** | AES-192, ECDH (Curve25519), ECDSA | AES-256, EdDSA (Ed25519), RSA 4096 |
| **Post-cuántico (PQC)** | ML-KEM-768 (Kyber), ML-DSA (Dilithium) | ML-KEM-1024, SLH-DSA (SPHINCS+), Falcon |

---

### 2.- Cifrados y Protocolos NO Recomendados (Obsoletos o Vulnerables):

| Tipo / Protocolo | Algoritmos / Cifrados a Evitar (Inseguros) |
| :--- | :--- |
| **Protocolos SSL/TLS obsoletos** | SSLv2, SSLv3, TLS 1.0, TLS 1.1 |
| **Cifrados de bloque débiles** | DES (40/56 bits), 3DES, RC2, RC4, IDEA, CAST, Blowfish, CAMELLIA-128, ARIA (sin modo AEAD) |
| **Modos de operación inseguros** | AES-CBC, AES-ECB, AES-CFB, AES-CTR (sin integridad) |
| **Intercambio de clave inseguro** | RSA estático (sin PFS), DH estático, ECDH estático, PSK, grupos DH < 2048 bits |
| **Funciones hash rotas** | MD5, SHA-1 |
| **Firma digital débil** | RSA < 2048 bits, DSA, ECDSA con curvas inseguras, ssh-rsa (sin SHA-2) |
| **IPsec** | IKEv1, grupos DH 2 y 5 (1024 bits) |
| **SSH** | SSH v1, cifrados: 3des-cbc, arcfour, blowfish-cbc; MACs: hmac-md5, hmac-sha1 |
| **WiFi** | WEP, WPA-TKIP, WPA2 con TKIP, WPS activado |
| **PGP/GPG** | RSA < 3072 bits, DSA, Twofish, Serpent, CAMELLIA, IDEA, CAST5 |
| **Almacenamiento** | MD5, 3DES, SHA-1, AES-128 (en contextos de alta seguridad) |

Vulnerabilidades conocidas asociadas: POODLE, BEAST, CRIME, Lucky13, Sweet32 (3DES), KRACK (WPA2), Dragonblood (WPA3), Logjam, DROWN, Heartbleed, ataques a CBC (bit flipping)

https://github.com/hackingyseguridad/cifrados/blob/main/ciffrados.md

### 3.- Escaneo subrutinas:

testssl.sh IP/rango 

sh scan_cifrados.sh lista de IP en ip.txt





http://www.hackingyseguridad.com/ 
