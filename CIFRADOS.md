### Cifrados: Auditoría Criptográfica y análisis 

---

### Tabla de Contenidos

1. [Conceptos Fundamentales](#conceptos-fundamentales)
2. [Clasificación de Cifrados](#clasificación-de-cifrados)
3. [Cifrados Débiles y Deprecados](#cifrados-débiles-y-deprecados)
4. [Cifrados Fuertes Recomendados](#cifrados-fuertes-recomendados)
5. [Auditoría y Testing](#auditoría-y-testing)
6. [Ataques Prácticos](#ataques-prácticos)
7. [Referencias Legales](#referencias-legales)

---

### Conceptos Fundamentales

### ¿Qué es un Cifrado?

Un cifrado es un algoritmo matemático que transforma datos legibles (texto plano) en datos ilegibles (texto cifrado) mediante el uso de una clave criptográfica. El objetivo es garantizar:

- **Confidencialidad:** Solo quien posea la clave puede descifrarlo
- **Integridad:** Se puede verificar que los datos no han sido modificados
- **Autenticación:** Se puede confirmar la identidad del emisor
- **No repudio:** El emisor no puede negar haber enviado el mensaje

### Componentes de un Sistema Criptográfico

| Componente | Descripción | Ejemplo |
|-----------|-----------|---------|
| **Algoritmo** | Proceso matemático de cifrado | AES, RSA, ChaCha20 |
| **Clave** | Valor secreto usado en el algoritmo | 256 bits aleatorios |
| **Texto Plano** | Datos originales sin cifrar | "Mensaje confidencial" |
| **Texto Cifrado** | Datos después de aplicar el cifrado | "A7F2K9L0M8..." |
| **Tamaño de Clave** | Longitud de la clave en bits | 128, 256, 4096 bits |

### Tipos de Criptografía

#### 1. Criptografía Simétrica

Usa la **misma clave** para cifrar y descifrar.

**Ventajas:**
- Rápida y eficiente
- Ideal para grandes volúmenes de datos
- Baja sobrecarga computacional

**Desventajas:**
- Problema de distribución de claves
- Si se compromete la clave, toda la comunicación es vulnerable
- Requiere un canal seguro para compartir la clave

**Ejemplos:** AES, ChaCha20, 3DES, Blowfish

#### 2. Criptografía Asimétrica

Usa un **par de claves**: clave pública (para cifrar) y clave privada (para descifrar).

**Ventajas:**
- Soluciona el problema de distribución de claves
- Permite firma digital
- Cada parte tiene control total de su clave privada

**Desventajas:**
- Mucho más lenta que criptografía simétrica
- Requiere claves más largas (2048-4096 bits)
- Mayor sobrecarga computacional

**Ejemplos:** RSA, ECDSA, EdDSA, ElGamal

#### 3. Funciones Hash Criptográficas

Convierte datos de cualquier tamaño en una cadena de tamaño fijo (resumen/fingerprint).

**Características:**
- **Determinista:** Mismo input siempre produce mismo output
- **Unidireccional:** Imposible recuperar datos originales del hash
- **Resistente a colisiones:** Debe ser computacionalmente imposible encontrar dos inputs que produzcan el mismo hash
- **Sensible al cambio:** Pequeños cambios en el input producen hashes completamente diferentes

**Ejemplos:** SHA-256, SHA-3, BLAKE2

---

## Clasificación de Cifrados

### Cifrados de Bloque vs. Cifrados de Flujo

| Característica | Cifrado de Bloque | Cifrado de Flujo |
|---|---|---|
| **Unidad de procesamiento** | Bloques fijos (128 bits típico) | Byte o bit individual |
| **Velocidad** | Moderada | Muy rápida |
| **Parallelizable** | Sí (con modos adecuados) | No (generalmente) |
| **Modo de operación** | Requiere modo (CBC, CTR, GCM) | Opera directamente |
| **Ejemplos** | AES, 3DES, Blowfish | ChaCha20, RC4 (deprecado), A5/1 |
| **Seguridad** | Alta si está bien implementado | Variable según diseño |

### Modos de Operación para Cifrados de Bloque

| Modo | Sigla | Características | Seguridad | Casos de Uso |
|---|---|---|---|---|
| **ECB** | Electronic CodeBook | Cada bloque se cifra independientemente | ❌ DÉBIL (patrones visibles) | NUNCA usar en producción |
| **CBC** | Cipher Block Chaining | Cada bloque depende del anterior | ⚠️ Buena (requiere IV) | Estándar heredado (TLS 1.2) |
| **CTR** | Counter | Convierte bloque en flujo | ✅ Excelente | TLS 1.3, almacenamiento |
| **GCM** | Galois/Counter Mode | CTR + autenticación | ✅ Excelente (AEAD) | Recomendado actualmente |
| **XTS** | XEX-based tweaked codebook | Con tweaks para datos relacionados | ✅ Excelente | Encriptación de discos (BitLocker, LUKS) |
| **EAX** | Encrypt-then-Authenticate-then-Translate | Modo autenticado | ✅ Bueno (AEAD) | Alternativa a GCM |

---

### Cifrados Débiles y Deprecados

### ❌ NUNCA Usar en Producción

#### 1. DES y 3DES (Triple DES)

```
Algoritmo: DES / 3DES
Tamaño de Clave: 56 bits / 168 bits (3DES)
Tamaño de Bloque: 64 bits
Estado: DEPRECADO desde 2013
```

**Problemas:**
- Tamaño de bloque demasiado pequeño (64 bits)
- Clave de DES muy corta (56 bits, quebrada en 1997)
- 3DES usa 3 veces más CPU pero no proporciona seguridad equivalente a claves modernas
- Vulnerable a ataques de colisión en modos CBC después de ~2³⁰ bloques (Sweet32, CVE-2016-2183)

**Referencias:**
- CVE-2016-2183 (Sweet32 Birthday Attack)
- RFC 8246 (Deprecación de DES y 3DES en TLS)

**Auditoría:**
```bash
# Comprobar qué cifrados soporta un servidor TLS
echo | openssl s_client -connect target.com:443 -cipher "DES:3DES" 2>/dev/null | grep -i cipher

# En SSH
ssh -Q cipher usuario@host | grep -E "3des|des"

# Forzar conexión con 3DES (solo para testing autorizado)
sshpass -p "password" ssh -c 3des-cbc usuario@host
```

---

#### 2. RC4 (Rivest Cipher 4)

```
Algoritmo: RC4
Tipo: Cifrado de flujo
Estado: PROHIBIDO en TLS 1.3 (RFC 7539)
```

**Problemas:**
- Claves debilitadas (bias en primeros bytes)
- Keystream predecible en ciertos contextos
- Vulnerable a ataques de reutilización de keystream
- CVE-2013-2566 (RC4 en HTTPS)

**Auditoría:**
```bash
# Detectar RC4 en TLS
nmap --script ssl-enum-ciphers -p 443 target.com | grep -i "RC4"

# OpenSSL
echo | openssl s_client -connect target.com:443 -cipher "RC4" 2>/dev/null
```

---

#### 3. MD5 y SHA-1

```
Algoritmo: MD5 / SHA-1
Tipo: Función Hash Criptográfica
Estado: DEPRECADO
```

| Aspecto | MD5 | SHA-1 |
|---|---|---|
| **Tamaño de salida** | 128 bits | 160 bits |
| **Colisiones encontradas** | Sí (2004) | Sí (2017, SHAttered) |
| **Vulnerabilidad** | Débil | Débil |
| **Estado legal** | Deprecado | Deprecado en FIPS 180-1 |

**Referencias:**
- CVE-2004-2761 (Colisiones MD5)
- SHAttered (https://shattered.io/) - Colisión SHA-1 práctica

**Auditoría:**
```bash
# Detectar certificados con MD5/SHA-1
openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text -noout | grep -i "signature\|algorithm"

# Buscar hashes débiles en aplicaciones
grep -r "md5(" código/ 
grep -r "SHA1" código/
```

---

#### 4. Otros Cifrados Débiles

| Cifrado | Problema | Alternativa |
|---------|----------|-----------|
| **Blowfish** | Bloque de 64 bits (Sweet32 vulnerable) | ChaCha20, AES-256 |
| **IDEA** | Obsoleto, lento | AES |
| **Serpent** | Nunca adoptado ampliamente | AES-256 |
| **Camellia** | Menos estudiado que AES | AES-256 |
| **CAST-128** | Débil, tamaño bloque 64-bit | AES |

---

### Cifrados Fuertes Recomendados

### Recomendados para 2026

#### 1. AES (Advanced Encryption Standard)

```
Algoritmo: AES / Rijndael
Tipo: Cifrado de bloque simétrico
Tamaño de Bloque: 128 bits (fijo)
Tamaño de Clave: 128, 192, 256 bits
Estándar: NIST FIPS 197
```

**Características:**
- Estándar federal estadounidense desde 2001
- Ampliamente adoptado en todo el mundo
- Altamente optimizado en hardware (AES-NI)
- Seguro para clasificación TOP SECRET

**Modos seguros:**
- **GCM** (Galois/Counter Mode) - Autenticado, recomendado
- **CTR** (Counter Mode) - Rápido, seguro
- **XTS** - Para encriptación de discos

**Variantes:**
- **AES-128:** Seguro hasta ~2030 (128 bits = 2⁶⁴ operaciones de colisión)
- **AES-192:** Seguro hasta ~2040
- **AES-256:** Seguro a largo plazo, resistente a ataques cuánticos teóricos

**Implementación segura:**
```bash
### Generar clave AES-256 aleatoria
openssl rand -hex 32

### Cifrar archivo con AES-256-GCM
openssl enc -aes-256-gcm -in archivo.txt -out archivo.txt.enc -pass pass:"contraseña" -P

### Descifrar
openssl enc -d -aes-256-gcm -in archivo.txt.enc -pass pass:"contraseña"

### Con archivo de clave (más seguro)
dd if=/dev/urandom of=key.bin bs=32 count=1
openssl enc -aes-256-cbc -in archivo.txt -out archivo.txt.enc -K $(xxd -p < key.bin) -iv 0000000000000000000000000000000
```

**Referencias:**
- NIST FIPS 197
- NIST SP 800-38D (GCM)
- NIST SP 800-38E (XTS)

---

#### 2. ChaCha20-Poly1305

```
Algoritmo: ChaCha20 (cifrado) + Poly1305 (MAC)
Tipo: AEAD (Authenticated Encryption with Associated Data)
Tamaño de Clave: 256 bits
Tamaño de Nonce: 96 bits
Inventor: Daniel J. Bernstein
```

**Ventajas:**
- Muy rápido sin hardware dedicado (mejor que AES en CPU antigua)
- Resistente a ataques de timing (time-constant)
- No requiere permiso de patentes
- Seguro y auditado
- Estándar en TLS 1.3 (RFC 7539)
- Usado en OpenSSH, WireGuard

**Características de seguridad:**
- Basado en 20 rondas de ChaCha
- Poly1305 proporciona autenticación fuerte
- AEAD = cifrado + autenticación combinados

**Uso práctico:**
```bash
### TLS con ChaCha20-Poly1305
echo | openssl s_client -connect example.com:443 -cipher "CHACHA20-POLY1305" 2>/dev/null

### SSH con ChaCha20-Poly1305
grep "chacha20-poly1305" ~/.ssh/config

### Openssh_config recomendada
cat >> ~/.ssh/config << 'EOF'
Host *
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
```

**Referencias:**
- RFC 7539 (ChaCha20 y Poly1305 para IETF)
- RFC 8439 (ChaCha20 y Poly1305 - Estándar IETF)

---

#### 3. Funciones Hash Criptográficas Modernas

| Función | Salida | Bloque | Estado | Uso |
|---------|--------|-------|--------|-----|
| **SHA-256** | 256 bits | 512 bits | ✅ Recomendado | Criptografía, blockchain |
| **SHA-512** | 512 bits | 1024 bits | ✅ Recomendado | Firmas, derivación de claves |
| **SHA-3 (Keccak)** | 224, 256, 384, 512 | Variable | ✅ Recomendado (futuro) | Estándar NIST 2015 |
| **BLAKE2** | 256, 512 bits | Variable | ✅ Recomendado | Rápido, criptográficamente fuerte |
| **BLAKE3** | 256 bits (extensible) | Variable | ✅ Nuevo (2021) | Muy rápido, parallelizable |

**Comparativa de velocidad (en CPU moderno):**

```
BLAKE2:    ~7 GB/s
ChaCha20:  ~2 GB/s
SHA-256:   ~1.5 GB/s
AES:       ~0.8 GB/s (sin AES-NI)
           ~8 GB/s (con AES-NI)
```

---

#### 4. Algoritmos Asimétricos Recomendados

| Algoritmo | Clave Mín | Clave Típ | Estado | Caso de Uso |
|-----------|-----------|-----------|--------|-----------|
| **RSA** | 2048 bits | 4096 bits | ✅ Confiable | Cifrado, firma, TLS |
| **ECDSA** | P-256 | P-384, P-521 | ✅ Recomendado | Firma, ECDH |
| **EdDSA** | 256 bits | 256 bits | ✅ Recomendado | Firma (SSH, criptografía moderna) |
| **ECDH** | P-256 | P-384, P-521 | ✅ Recomendado | Intercambio de claves |
| **X25519** | 256 bits | 256 bits | ✅ Recomendado | Intercambio de claves (post-cuántico resistente) |

---

### Auditoría y Testing

### 1. Auditoría de TLS/SSL

#### Herramientas principales

```bash
### nmap + ssl-enum-ciphers
nmap --script ssl-enum-ciphers -p 443 target.com

### testssl.sh (auditoría completa)
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh target.com:443

### openssl
echo | openssl s_client -connect target.com:443 -tls1_2 2>/dev/null | grep -i cipher

### sslscan
sslscan --no-failed target.com:443

### ssllabs grader
curl -X GET "https://api.ssllabs.com/api/v3/analyze?host=target.com&publish=off&all=done"
```

**Ejemplo práctico:**
```bash
#!/bin/bash
# audit_tls.sh - Auditoría simple de cifrados TLS

TARGET=$1
PORT=${2:-443}

echo "[*] Comprobando cifrados TLS en $TARGET:$PORT"
echo "[*] Protocolo TLS 1.2:"
echo | openssl s_client -connect $TARGET:$PORT -tls1_2 2>/dev/null | grep "Cipher"

echo "[*] Protocolo TLS 1.3:"
echo | openssl s_client -connect $TARGET:$PORT -tls1_3 2>/dev/null | grep "Cipher"

echo "[*] Certificado:"
echo | openssl s_client -connect $TARGET:$PORT 2>/dev/null | openssl x509 -text -noout | grep -E "Subject:|Issuer:|Signature algorithm"
```

---

### 2. Auditoría de SSH

```bash
### Ver cifrados disponibles
ssh -Q cipher host
ssh -Q cipher-auth host  
ssh -Q mac host
ssh -Q kex host
ssh -Q key host

### Fuerza bruta de cifrados (testing autorizado)
for cipher in $(ssh -Q cipher host 2>/dev/null | tr '\n' ','); do
    echo -n "Testing $cipher: "
    timeout 3 ssh -c "$cipher" user@host "echo OK" 2>/dev/null && echo "OK" || echo "FAIL"
done

### Comprobar qué soporta el servidor
ssh -vvv user@host 2>&1 | grep -i "kex\|cipher\|mac\|key"
```

**Script de auditoría SSH:**
```bash
#!/bin/bash
# audit_ssh.sh

TARGET=$1
USER=${2:-root}

echo "[*] Auditoría SSH de $TARGET"

### Conectar y mostrar configuración
ssh -vvv $USER@$TARGET "exit" 2>&1 | grep -E "server.*offer|kex_algorithms|ciphers|macs|host.*algorithm" | sort -u

echo ""
echo "[*] Información del servidor SSH:"
timeout 5 bash -c "exec 3<>/dev/tcp/$TARGET/22; cat <&3" | head -1
```

---

### 3. Análisis de Implementación

```bash
### Detectar cifrados débiles en código fuente
grep -r "DES\|RC4\|MD5\|SHA1" --include="*.py" --include="*.js" --include="*.java" código/

### Analizar dependencias de criptografía
pip show cryptography
npm list crypto
gem list openssl

### Verificar versión de OpenSSH
ssh -V | grep -oP 'OpenSSH_\K[0-9.]+'

### Verificar OpenSSL
openssl version
```

---

### Ataques Prácticos

### 1. Ataque de Fuerza Bruta contra Cifrados Débiles

```bash
### Contra DES (64 bits, quebrable en ~15 horas con GPU moderna)
hashcat -m 1500 -a 3 hash.txt ?a?a?a?a?a?a?a?a

### Contra hashes débiles (MD5)
hashcat -m 0 hash.txt wordlist.txt

### Fuerza bruta online contra web
hydra -l usuario -P wordlist.txt http-post-form://target.com/login:user=^USER^&pass=^PASS^
```

---

### 2. Ataque Sweet32 (CVE-2016-2183)

Afecta a cifrados con bloques de 64 bits (DES, 3DES, Blowfish) en modo CBC.

```bash
### Detectar vulnerability Sweet32
echo | openssl s_client -connect target.com:443 -cipher "DES:3DES:BF" 2>/dev/null | grep -i cipher

### POC: Capturar tráfico y esperar 2^32 bloques (~34GB)
tcpdump -i eth0 -w capture.pcap host target.com
```

---

### 3. Downgrade Attack (SSLv3 POODLE)

```bash
### Intentar conectar con SSLv3 (inseguro)
echo | openssl s_client -connect target.com:443 -ssl3 2>/dev/null

### Verificar con nmap
nmap --script ssl-enum-ciphers -p 443 --script-args sslversion=ssl3 target.com
```

---

### 4. Extracción de Tráfico Cifrado

```bash
### Capturar tráfico con cifrados débiles
bettercap -iface eth0

### En bettercap (si server usa ciphers débiles):
> net.probe on
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on
> set net.sniff.output sniff.pcap
```

---

### Referencias Normativas y Legales

### Estándares de Criptografía

| Documento | Descripción |
|-----------|-------------|
| **NIST FIPS 197** | Estándar AES |
| **NIST FIPS 180-4** | Estándar SHA |
| **NIST SP 800-38D** | Modos AEAD (GCM, CCM) |
| **RFC 7539** | ChaCha20-Poly1305 |
| **RFC 7748** | Elliptic Curves for Security (X25519) |
| **RFC 8446** | TLS 1.3 (últimas recomendaciones) |

### Referencias de Vulnerabilidades

- **CVE-2016-2183** - Sweet32 Birthday Attack (DES, 3DES)
- **CVE-2013-2566** - RC4 Biases
- **CVE-2014-0160** - Heartbleed (OpenSSL)
- **CVE-2018-12326** - ChaCha20 nonce reuse
- **CVE-2024-6387** - regreSSHion (OpenSSH)

### OWASP

- **OWASP A02:2021** – Cryptographic Failures
- **OWASP Cryptographic Storage Cheat Sheet**
- **OWASP Cryptographic Failures Prevention**

### Regulaciones Legales

#### España - Código Penal

- **Art. 197.1 CP:** Acceso a datos protegidos sin consentimiento ✅ Necesita **autorización previa**
- **Art. 197.2 CP:** Divulgación de datos protegidos = Pena de 1-4 años
- **Art. 198 CP:** Acceso fraudulento a sistemas = Pena de 6 meses-2 años

#### Unión Europea

- **RGPD (Reglamento 2016/679):** Protección de datos personales - Artículos 32-34 (encriptación obligatoria)
- **Directiva NIS 2 (2022/2555):** Seguridad de redes e información

#### Autorización Previa

**Requisitos antes de realizar cualquier auditoría de criptografía:**

1. Contrato de pentest firmado
2. Autorización explícita del propietario/CTO
3. Alcance definido (IP, puertos, fechas)
4. Plan de remediación acordado
5. Confidencialidad y NDA

---

## Recomendaciones Finales

### Para Servidores Modernos (2026)

```
DEBE SOPORTAR:
- TLS 1.3
- ChaCha20-Poly1305
- AES-256-GCM
- ECDHE con X25519 o P-384
- Ed25519 para firmas

NUNCA:
- SSLv3, TLS 1.0, TLS 1.1
- DES, 3DES, RC4
- MD5, SHA-1
- ECB mode
```

### Para Auditoría Segura

```bash
### Auditoría completa con testssl.sh
./testssl.sh --full --json target.com:443 > audit_$(date +%Y%m%d).json

### Verificar cumplimiento NIST
./testssl.sh --severity HIGH target.com:443

### Monitoreo continuo
watch -n 3600 'testssl.sh --json target.com:443 >> audit_continuous.log'
```

---
