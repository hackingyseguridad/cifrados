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



https://github.com/hackingyseguridad/cifrados/blob/main/ciffrados.md

### 1.- Escaneo subrutinas

testssl.sh IP/rango 

sh scan_cifrados.sh lista de IP en ip.txt





http://www.hackingyseguridad.com/
