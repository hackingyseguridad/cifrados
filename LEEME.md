### Cifrados recomendados 

![Hacking y Seguridad](http://hackingyseguridad.com/banner.png)

> **Repositorio oficial de algoritmos, protocolos y cifrados seguros recomendados para implementaciones criptográficas modernas.**

### Tabla de Contenidos

- [Introducción](#introducción)
- [Niveles de Seguridad](#niveles-de-seguridad)
- [Cifrados y Protocolos Recomendados](#1--cifrados-y-protocolos-recomendados)
- [Cifrados NO Recomendados](#2--cifrados-y-protocolos-no-recomendados)
- [Certificados Digitales](#3--certificados-digitales)
- [Herramientas de Escaneo](#4--herramientas-de-escaneo)
- [Guía de Instalación](#guía-de-instalación)
- [Casos de Uso](#casos-de-uso)
- [Referencias](#referencias)
- [Contribuciones](#contribuciones)

---

### Introducción

Este repositorio contiene una guía completa sobre **criptografía moderna**, cifrados seguros y protocolos de seguridad recomendados

### Objetivo

Proporcionar recomendaciones actualizadas sobre qué cifrados usar, cuáles evitar y por qué, considerando tanto la seguridad a corto plazo como la resistencia post-cuántica.

---

### Niveles de seguridad

Este repositorio clasifica las recomendaciones en **4 niveles de seguridad**:

| Nivel | Descripción | Casos de Uso | Archivos |
|-------|-------------|-------------|----------|
| 🔴 **Seguridad Baja** | Cifrados legacy, no recomendados para datos sensibles | Sistemas heredados, compatibilidad | `seguridad_baja.txt` |
| 🟠 **Seguridad Media** | Aceptables para la mayoría de aplicaciones comerciales | E-commerce, aplicaciones web, HTTPS | `seguridad_media.txt` |
| 🟢 **Seguridad Alta** | Recomendado para datos muy sensibles y financieros | Banca, datos personales, HIPAA | `seguridad_alta.txt` |
| 🔵 **Seguridad Militar** | Nivel máximo, usado en contextos de defensa | Secretos de estado, datos clasificados | `seguridad_militar.txt` |

---

### Protocolos recomendados

### Tabla Comparativa - Protocolos TLS/SSL

| Protocolo | Estado | Año | Recomendación | Notas |
|-----------|--------|------|----------------|--------|
| **SSLv2** | ❌ Roto | 1995 | 🚫 NO USAR | Completamente comprometido (DROWN) |
| **SSLv3** | ❌ Roto | 1996 | 🚫 NO USAR | Vulnerable a POODLE |
| **TLS 1.0** | ❌ Deprecado | 1999 | 🚫 NO USAR | Vulnerable a ataques (BEAST) |
| **TLS 1.1** | ❌ Deprecado | 2006 | 🚫 NO USAR | No soporta AEAD, POODLE |
| **TLS 1.2** | ✅ Soportado | 2008 | 🟠 ACEPTABLE | Con cifrados modernos (GCM) |
| **TLS 1.3** | ✅ Actual | 2018 | 🟢 RECOMENDADO | Estado del arte, eliminó debilidades |
| **TLS 1.4** | ⏳ Propuesto | ~2026 | 🟢 FUTURO | En desarrollo, post-cuántico |

### 🔐 Cifrados Simétricos Recomendados

| Cifrado | Tamaño Clave | Modo | Seguridad | Comentario |
|---------|-------------|------|----------|-----------|
| **AES-128** | 128 bits | GCM | 🟠 Media | Aceptable, estándar NIST |
| **AES-192** | 192 bits | GCM | 🟢 Alta | Buen balance seguridad/rendimiento |
| **AES-256** | 256 bits | GCM | 🟢 Muy Alta | Máxima seguridad (recomendado) |
| **ChaCha20-Poly1305** | 256 bits | AEAD | 🟢 Muy Alta | Rápido en CPU sin AES-NI |
| **AES-GCM** | 128-256 | AEAD | 🟢 Alta | Integridad + confidencialidad |

⚠️ **Modos INSEGUROS**: AES-ECB, AES-CBC (sin HMAC), AES-CTR (sin integridad)

### 🔑 Intercambio de Claves (Key Exchange)

| Método | Tamaño | Seguridad | PFS | Recomendación |
|--------|--------|----------|-----|----------------|
| **ECDHE-P256** | 256 bits | 🟠 Media | ✅ Sí | Aceptable |
| **ECDHE-P384** | 384 bits | 🟢 Alta | ✅ Sí | Recomendado |
| **ECDHE-P521** | 521 bits | 🟢 Muy Alta | ✅ Sí | Máxima seguridad |
| **X25519** | 256 bits | 🟢 Alta | ✅ Sí | Moderno y rápido |
| **X448** | 448 bits | 🟢 Muy Alta | ✅ Sí | Mayor seguridad que X25519 |
| **DH grupal < 2048** | 1024 bits | 🔴 Baja | ❌ No | Vulnerable (Logjam) |
| **DH grupo 14** | 2048 bits | 🟠 Media | ✅ Sí | Mínimo aceptable |
| **DH grupo 19** | 256 bits Curva | 🟢 Alta | ✅ Sí | ECDH moderno |
| **DH grupo 21** | 512 bits Curva | 🟢 Muy Alta | ✅ Sí | Máxima seguridad |

**PFS = Perfect Forward Secrecy** (si se compromete la clave privada, sesiones pasadas permanecen seguras)

### 🏷️ Funciones Hash (Digest)

| Hash | Tamaño | Colisiones | Seguridad | Uso |
|------|--------|-----------|----------|-----|
| **MD5** | 128 bits | ❌ Encontradas | 🔴 NO USAR | Completamente roto |
| **SHA-1** | 160 bits | ❌ Prácticas | 🔴 NO USAR | Deprecated en HTTPS |
| **SHA-256** | 256 bits | ✅ Seguro | 🟢 Recomendado | Estándar actual |
| **SHA-384** | 384 bits | ✅ Seguro | 🟢 Recomendado | Mayor seguridad |
| **SHA-512** | 512 bits | ✅ Seguro | 🟢 Recomendado | Máxima seguridad |
| **SHA-3** | 256/512 | ✅ Seguro | 🟢 Futuro | Estándar moderno |
| **BLAKE2** | Variable | ✅ Seguro | 🟢 Rápido | Más rápido que MD5 |

### 📝 Firma Digital (Digital Signatures)

| Algoritmo | Tamaño Clave | Seguridad | Velocidad | Recomendación |
|-----------|-------------|----------|-----------|----------------|
| **RSA-2048** | 2048 bits | 🔴 Débil | 🐢 Lenta | NO USAR |
| **RSA-3072** | 3072 bits | 🟠 Aceptable | 🐢 Lenta | Aceptable (legacy) |
| **RSA-4096** | 4096 bits | 🟢 Alta | 🐢 Lenta | Recomendado RSA |
| **ECDSA-P256** | 256 bits | 🟠 Media | 🐇 Rápida | Aceptable |
| **ECDSA-P384** | 384 bits | 🟢 Alta | 🐇 Rápida | Recomendado ECDSA |
| **EdDSA (Ed25519)** | 256 bits | 🟢 Muy Alta | 🚀 Muy Rápida | ✅ MEJOR OPCIÓN |
| **EdDSA (Ed448)** | 456 bits | 🟢 Extrema | 🚀 Muy Rápida | Máxima seguridad |

**Ed25519 es la mejor opción moderna**: segura, rápida y sin vulnerabilidades conocidas.

### 🔌 Protocolos Específicos

#### SSH v2 (Recomendado)

| Componente | Recomendado (Seguridad Media) | Recomendado (Seguridad Alta) |
|-----------|--------------------------------|------------------------------|
| **Host Key** | ecdsa-sha2-nistp256, ssh-ed25519 | ssh-ed25519 |
| **Key Exchange** | curve25519-sha256 | curve25519-sha256 |
| **Encryption** | aes256-ctr, chacha20-poly1305 | chacha20-poly1305, aes256-gcm |
| **MAC** | hmac-sha2-256 | hmac-sha2-512 |
| **Compression** | Desactivada | Desactivada |

```bash
# Configuración SSH segura (/etc/ssh/sshd_config)
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

#### IPsec (IKEv2)

| Parámetro | Seguridad Media | Seguridad Alta |
|-----------|-----------------|-----------------|
| **Protocolo** | IKEv2 | IKEv2 (no IKEv1) |
| **Autenticación** | SHA-256 | SHA-512 |
| **Cifrado** | AES-256 | AES-256 + ChaCha20 |
| **Grupo DH** | Grupo 19 (256 bits) | Grupo 21 (512 bits) |
| **Integridad** | SHA-256 | SHA-512 |

#### WPA/WiFi

| Estándar | Seguridad | Recomendación | Notas |
|----------|----------|----------------|-------|
| **WEP** | 🔴 Roto | ❌ NO USAR | 40-bit IV, completamente comprometido |
| **WPA** | 🔴 Roto | ❌ NO USAR | Vulnerable a KRACK |
| **WPA2-Personal** | 🟠 Media | Aceptable | Mejor que WPA |
| **WPA2-Enterprise** | 🟢 Alta | Recomendado | Con 802.1X |
| **WPA3-Personal** | 🟢 Alta | ✅ Recomendado | SAE, Opportunistic Wireless Encryption |
| **WPA3-Enterprise** | 🟢 Muy Alta | ✅ MEJOR | AES-192/256, 192-bit encryption |

#### PGP/GPG

| Componente | Recomendado (Media) | Recomendado (Alta) |
|-----------|----------------------|----------------------|
| **Cifrado Simétrico** | AES-192 | AES-256 |
| **Cifrado Asimétrico** | ECDH Curve25519 | ECDH Curve25519 + X448 |
| **Firma** | ECDSA P-256 o EdDSA | EdDSA (Ed25519) |
| **Hash** | SHA-256 | SHA-512 |
| **Tamaño RSA (si se usa)** | 3072 bits | 4096 bits |

### 🔮 Post-Cuántico (Quantum-Safe)

| Algoritmo | Tipo | Tamaño Clave | Estado | Recomendación |
|-----------|------|-------------|--------|----------------|
| **ML-KEM-768** (Kyber) | Encapsulación | 768 bits | 🟢 NIST PQC | Media/Alta |
| **ML-KEM-1024** | Encapsulación | 1024 bits | 🟢 NIST PQC | Muy Alta |
| **ML-DSA** (Dilithium) | Firma | 2544 bytes | 🟢 NIST PQC | Recomendado |
| **SLH-DSA** (SPHINCS+) | Firma | Variable | 🟢 NIST PQC | Stateless |
| **Falcon** | Firma | 897 bytes | 🟢 NIST PQC | Compacto |

> **Nota**: Los algoritmos post-cuánticos de NIST (2024) son los más actuales y recomendados.

---

## 2️⃣ Cifrados y Protocolos NO Recomendados

### 🔴 Matriz de Cifrados INSEGUROS

| Categoría | Algoritmos | Vulnerabilidades | Riesgo |
|-----------|-----------|-----------------|--------|
| **Cifrados de Bloque Débiles** | DES, 3DES, RC2 | Tamaño clave insuficiente, colisiones | 🔴 CRÍTICO |
| **Cifrados Stream** | RC4 | Bias en el keystream (CHAOS) | 🔴 CRÍTICO |
| **Cifrados Modernos (Mal Usados)** | AES-ECB, AES-CBC | Patrones, bit-flipping | 🔴 CRÍTICO |
| **Funciones Hash** | MD5, SHA-1 | Colisiones prácticas | 🔴 CRÍTICO |
| **Intercambio Claves** | Diffie-Hellman < 2048 | Logjam, pre-computation | 🔴 CRÍTICO |

### 📋 Vulnerabilidades por Protocolo/Algoritmo

| Vulnerabilidad | Afecta a | Año | CVSS | Mitigación |
|----------------|----------|------|------|-----------|
| **POODLE** | SSLv3, TLS 1.0 | 2014 | 7.1 | Deshabilitar SSLv3 |
| **Heartbleed** | OpenSSL < 1.0.1g | 2014 | 7.5 | Actualizar OpenSSL |
| **FREAK** | OpenSSL, exportación | 2015 | 5.9 | Usar TLS 1.2+ |
| **Logjam** | DH < 2048 bits | 2015 | 5.9 | Usar DH >= 2048 o ECDHE |
| **DROWN** | SSLv2 | 2016 | 7.5 | Deshabilitar SSLv2 |
| **Sweet32** | 3DES, Blowfish | 2016 | 6.8 | No usar 3DES |
| **KRACK** | WPA2-TKIP | 2017 | 8.1 | Usar WPA2-AES o WPA3 |
| **BEAST** | AES-CBC en TLS 1.0 | 2011 | 5.9 | Usar TLS 1.2+ |
| **Lucky13** | CBC mode en TLS | 2013 | 5.1 | Usar AEAD (GCM) |
| **CRIME** | Compresión TLS | 2012 | 7.5 | Deshabilitar compresión |

### Protocolos Específicos a EVITAR

```yaml
SSH v1:
  - ❌ Completamente roto
  - Usar: SSH v2 siempre

Cifrados SSH a evitar:
  - 3des-cbc, arcfour, blowfish-cbc
  - hmac-md5, hmac-sha1 (sin -etm)
  
IKEv1:
  - ❌ Obsoleto
  - Usar: IKEv2 siempre
  
Grupos DH:
  - ❌ Grupo 1 (768 bits) - Totalmente roto
  - ❌ Grupo 2 (1024 bits) - Vulnerable a Logjam
  - ✅ Mínimo: Grupo 14 (2048 bits)
  
WEP/WPA:
  - ❌ Completamente comprometido
  - Usar: WPA2-AES o WPA3 siempre
```

---

## 3️⃣ Certificados Digitales

> Para una guía completa sobre certificados, consulta: **[Certificados Digitales](https://github.com/hackingyseguridad/certificado/)**

### Recomendaciones Rápidas

| Aspecto | Recomendación | Por qué |
|--------|----------------|--------|
| **Autoridad Certificadora** | CA reconocida (Let's Encrypt, Sectigo, etc.) | Validación de confianza |
| **Algoritmo Firma** | SHA-256, SHA-384, SHA-512 | SHA-1 está deprecado |
| **Algoritmo Clave** | RSA-2048+, ECDSA-P256+, EdDSA | Resistencia |
| **Tipo Certificado** | DV, OV, EV (según necesidad) | Validación de dominio/organización |
| **Validez** | 1 año máximo (90 días recomendado) | Rotación frecuente = seguridad |
| **SAN** | Múltiples dominios si es necesario | Flexibilidad y costo |
| **OCSP Stapling** | Habilitado | Revocación sin latencia |

### Herramientas para Verificar Certificados

```bash
# Ver detalles del certificado
openssl x509 -in cert.pem -text -noout

# Verificar cadena de certificados
openssl verify -CAfile ca.pem cert.pem

# Verificar con OpenSSL s_client
openssl s_client -connect example.com:443 -showcerts
```

---

## 4️⃣ Herramientas de Escaneo

Este repositorio incluye herramientas automáticas para auditar la seguridad criptográfica:

### 🔧 testssl.sh

**Descripción**: Auditoría completa de TLS/SSL en servidores web

**Uso**:
```bash
./testssl.sh https://ejemplo.com
./testssl.sh 192.168.1.1:443
./testssl.sh --full ejemplo.com
./testssl.sh --json=results.json ejemplo.com
```

**Funcionalidades**:
- ✅ Detecta versión TLS/SSL
- ✅ Enumera cifrados soportados
- ✅ Identifica vulnerabilidades conocidas
- ✅ Genera reportes en JSON/HTML
- ✅ Verifica certificados
- ✅ Pruebas de OCSP, CRL
- ✅ Análisis de seguridad PFS

**Requisitos**: bash, openssl, curl

### 📡 scan_cifrados.sh

**Descripción**: Escanea múltiples direcciones IP y clasifica por nivel de seguridad

**Uso**:
```bash
sh scan_cifrados.sh
# Lee IPs desde: ip.txt (una por línea)

# Archivo ip.txt:
192.168.1.1:443
10.0.0.1:22
ejemplo.com:443
```

**Salida**:
- Clasifica en: `seguridad_alta.txt`, `seguridad_media.txt`, `seguridad_baja.txt`, `seguridad_militar.txt`
- Genera reportes por nivel de seguridad

### 🔦 filtro.sh

**Descripción**: Filtra y procesa resultados de escaneos

**Uso**:
```bash
./filtro.sh <archivo_entrada> <filtro>
# Ejemplo:
./filtro.sh resultados.txt "AES-256"
```

---

## Guía de Instalación

### Requisitos Previos

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y openssl curl bash git

# CentOS/RHEL
sudo yum install -y openssl curl bash git

# macOS
brew install openssl curl bash
```

### Descarga del Repositorio

```bash
git clone https://github.com/hackingyseguridad/cifrados.git
cd cifrados
chmod +x testssl.sh scan_cifrados.sh filtro.sh
```

### Configuración Inicial

```bash
# Crear archivo de IPs para escanear
cat > ip.txt << EOF
ejemplo.com:443
192.168.1.1:443
10.0.0.1:22
EOF

# Ejecutar escaneo
sh scan_cifrados.sh

# Ver resultados
cat seguridad_alta.txt
cat seguridad_media.txt
cat seguridad_baja.txt
```

---

## Casos de Uso

### 🌐 Asegurar Servidor Web (Apache/Nginx)

```bash
# 1. Auditar servidor actual
./testssl.sh https://tu-servidor.com

# 2. Implementar configuración segura
# En Apache: /etc/apache2/mods-enabled/ssl.conf
SSLProtocol -all +TLSv1.3 +TLSv1.2
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLCurves X25519:X448:secp384r1

# En Nginx: /etc/nginx/nginx.conf
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
```

### 🔑 Configurar SSH Seguro

```bash
# Editar /etc/ssh/sshd_config
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Reiniciar SSH
sudo systemctl restart sshd

# Verificar configuración
ssh-audit tu-servidor.com
```

### 🛡️ Auditoría de Seguridad Empresarial

```bash
# Crear lista de servidores
echo "servidor1.empresa.com" > servidores.txt
echo "servidor2.empresa.com" >> servidores.txt
echo "db.empresa.com:3306" >> servidores.txt

# Escanear todos
for server in $(cat servidores.txt); do
    echo "Escaneando $server..."
    ./testssl.sh "$server" --json="$server.json"
done

# Analizar resultados
grep -r "FAILED" *.json > fallos.txt
```

### 🔐 Migración a Post-Cuántico

```bash
# 1. Auditar algoritmos actuales
./testssl.sh tu-servidor.com | grep "Cipher"

# 2. Planificar migración
# - Fase 1: TLS 1.3 + ECDHE moderno
# - Fase 2: Híbrido con ML-KEM-768
# - Fase 3: ML-KEM-1024 + ML-DSA

# 3. Implementar en OpenSSL 3.0+
# (Próximas versiones incluirán soporte PQC nativo)
```

---

## 📊 Resumen Rápido - ¿Qué usar?

### Por Tipo de Servicio

| Servicio | Protocolo | Cifrado | Key Exchange | Hash | Firma |
|----------|-----------|---------|--------------|------|-------|
| **HTTPS** | TLS 1.3 | AES-256-GCM | X25519 | SHA-256 | ECDSA-P384 |
| **SSH** | SSH v2 | ChaCha20-Poly1305 | curve25519-sha256 | SHA-256 | Ed25519 |
| **IPsec** | IKEv2 | AES-256 | DH-21 (512-bit) | SHA-512 | EdDSA |
| **VPN** | WireGuard | ChaCha20-Poly1305 | X25519 | BLAKE2 | Ed25519 |
| **WiFi** | WPA3 | AES-256-GCMP | SAE | SHA-384 | N/A |
| **Base de Datos** | TLS 1.3 | AES-256-GCM | ECDHE-P384 | SHA-256 | Ed25519 |
| **Almacenamiento** | AES-256 | AES-256 (XTS) | Derivación clave | SHA-512 | N/A |
| **Correo** | TLS 1.3 | AES-256-GCM | ECDHE-P256 | SHA-256 | EdDSA |

### Por Nivel de Seguridad

```
🟢 SEGURIDAD ALTA (Recomendado para 2024-2026):
   - TLS 1.3 / SSH v2 / IKEv2
   - AES-256-GCM o ChaCha20-Poly1305
   - ECDHE con curvas modernas (P-384, X25519, X448)
   - SHA-256/384/512
   - EdDSA (Ed25519) para firmas

🟠 SEGURIDAD MEDIA (Aceptable con cuidado):
   - TLS 1.2 con cifrados GCM
   - AES-128-GCM (no recomendado solo)
   - ECDHE-P256 mínimo
   - SHA-256 mínimo
   - ECDSA-P256 o RSA-3072+

🔴 SEGURIDAD BAJA (NO USAR):
   - SSLv3, TLS 1.0, TLS 1.1
   - DES, 3DES, RC4, Blowfish
   - MD5, SHA-1
   - DH < 2048 bits
   - RSA < 2048 bits
```

---

## 📚 Estructura del Repositorio

```
cifrados/
├── README.md                      # Este archivo
├── ciffrados.md                   # Guía detallada de cifrados
├── testssl.sh                     # Auditoría de TLS/SSL
├── scan_cifrados.sh               # Escaneo múltiples servidores
├── filtro.sh                      # Procesar resultados
├── AES-128-simetico/              # Ejemplos AES-128
├── seguridad_alta.txt             # Resultado: servidores seguros
├── seguridad_media.txt            # Resultado: seguridad media
├── seguridad_baja.txt             # Resultado: servidores inseguros
└── seguridad_militar.txt          # Resultado: máxima seguridad
```

---

## 🔗 Referencias y Recursos

### Estándares Oficiales

- 📘 [NIST Special Publication 800-175B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf) - Guía de Criptografía
- 📘 [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- 📘 [RFC 8308 - SSH Algoritmos](https://tools.ietf.org/html/rfc8308)
- 📘 [RFC 7539 - ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539)

### Documentación de Seguridad

- 🛡️ [OWASP - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- 🛡️ [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- 🛡️ [SANS Top 25 Weaknesses](https://www.sans.org/top25/)
- 🛡️ [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

### Herramientas Relacionadas

- 🔧 [testssl.sh](https://github.com/drwetter/testssl.sh) - Auditoría TLS
- 🔧 [ssh-audit](https://github.com/jtesta/ssh-audit) - Auditoría SSH
- 🔧 [OpenSSL](https://www.openssl.org/) - Herramienta estándar
- 🔧 [Wireshark](https://www.wireshark.org/) - Análisis de tráfico

### Artículos Técnicos

- 📄 Criptografía Post-Cuántica
- 📄 Vulnerabilidades TLS Históricas
- 📄 Migración de Algoritmos Legacy
- 📄 Gestión de Certificados

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. **Fork** el repositorio
2. **Crea una rama** para tu feature (`git checkout -b feature/MiMejora`)
3. **Commit** tus cambios (`git commit -am 'Añade nueva información'`)
4. **Push** a la rama (`git push origin feature/MiMejora`)
5. **Abre un Pull Request**

### Áreas donde Contribuir

- ✨ Nuevos cifrados/protocolos (post-cuántico, etc.)
- ✨ Traducciones a otros idiomas
- ✨ Ejemplos de configuración
- ✨ Herramientas de auditoría
- ✨ Correcciones y actualizaciones
- ✨ Documentación mejorada

---

## ⚖️ Licencia

Este proyecto está bajo licencia **MIT**. Consulta [LICENSE](LICENSE) para más detalles.

---

## 📞 Contacto y Soporte

- 🌐 **Sitio Web**: [www.hackingyseguridad.com](http://www.hackingyseguridad.com/)
- 📧 **GitHub**: [hackingyseguridad](https://github.com/hackingyseguridad)
- 🐛 **Issues**: [Reportar problema](https://github.com/hackingyseguridad/cifrados/issues)

---

## ⚠️ Disclaimer

Este repositorio proporciona información sobre seguridad criptográfica. El uso de esta información es bajo tu responsabilidad. No nos hacemos responsables de:

- Daños causados por configuraciones incorrectas
- Pérdida de datos o sistemas
- Uso malintencionado de esta información
- Cambios en estándares de seguridad después de la publicación

**Siempre consulta con profesionales de seguridad antes de implementar en producción.**

---

## 📈 Estado del Proyecto

| Aspecto | Estado |
|--------|--------|
| Última Actualización | Julio 2026 |
| Versión | 2.0 |
| Mantenimiento | 🟢 Activo |
| Estabilidad | 🟢 Estable |
| Cobertura Post-Cuántico | 🟠 En Desarrollo |

---

**Hecho con ❤️ por la comunidad de Hacking y Seguridad**
