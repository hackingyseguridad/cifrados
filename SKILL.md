---
name: cifrados-audit
description: >
  Usar esta skill SIEMPRE que el usuario quiera realizar auditoría, testing, análisis,
  evaluación de fortaleza o explotación de cifrados débiles en servidores, aplicaciones
  o comunicaciones. Activar cuando se mencionen: cifrados, criptografía, TLS, SSL, SSH,
  AES, RSA, ChaCha20, MD5, SHA-1, DES, 3DES, RC4, cifrados débiles, análisis criptográfico,
  audit de seguridad criptográfica, cipher audit, algoritmos obsoletos, CVSS criptográfico,
  intercambio de claves, certificados digitales. También activar cuando el usuario quiera:
  comprobar fortaleza de cifrados, detectar cifrados deprecados, generar claves seguras,
  analizar suite criptográfica, testear TLS/SSL, evaluar vulnerabilidades criptográficas.
  Repositorio de referencia: https://github.com/hackingyseguridad/cifrados
---

# Cifrados Audit Skill — hackingyseguridad/cifrados

Skill de auditoría ofensiva de criptografía en sistemas objetivo. Cubre reconocimiento de
suite criptográfica → análisis de fortaleza → detección de cifrados débiles/deprecados →
explotación de vulnerabilidades criptográficas → hardening recomendado → documentación
de hallazgos en informe de seguridad.

---

## FASE 1 — Reconocimiento de Suite Criptográfica

### 1.1 Auditoría de TLS/SSL en servidores web

```bash
# Herramientas principales
testssl.sh https://target.com:443
nmap --script ssl-enum-ciphers -p 443 target.com
sslscan --no-failed target.com:443
ssllabs-scan --publish=off target.com

# OpenSSL manual — conectar y obtener cifrados ofrecidos
echo | openssl s_client -connect target.com:443 -tls1_2 2>/dev/null | grep "Cipher"
echo | openssl s_client -connect target.com:443 -tls1_3 2>/dev/null | grep "Cipher"

# Obtener certificado completo
openssl s_client -connect target.com:443 -showcerts 2>/dev/null

# Script rápido de auditoría TLS
#!/bin/bash
TARGET=$1
echo "[*] Escaneando $TARGET:443"
echo "[*] TLS 1.2:"
echo | openssl s_client -connect $TARGET:443 -tls1_2 2>/dev/null | grep Cipher
echo "[*] TLS 1.3:"
echo | openssl s_client -connect $TARGET:443 -tls1_3 2>/dev/null | grep Cipher
echo "[*] Certificado:"
echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -text -noout | grep -E "Subject:|Issuer:|Signature algorithm"
```

### 1.2 Auditoría de SSH

```bash
# Obtener versión y algoritmos disponibles
ssh -vvv usuario@target.com 2>&1 | grep -E "kex_algorithms|server_host_key_algorithms|encryption_algorithms|mac_algorithms"

# Herramienta ssh-audit (recomendada)
ssh-audit target.com
ssh-audit -p 2222 target.com
ssh-audit -j audit_$(date +%Y%m%d).json target.com  # JSON output

# Con nmap
nmap -p 22 --script ssh2-enum-algos target.com

# Listar algoritmos disponibles en servidor SSH
ssh -Q cipher usuario@target.com
ssh -Q mac usuario@target.com
ssh -Q kex usuario@target.com
ssh -Q key-alg usuario@target.com
```

### 1.3 Tabla de decisión — Protocolo a auditar

| Protocolo | Puerto | Herramienta Primaria | Herramienta Alternativa | Complejidad |
|-----------|--------|----------------------|-------------------------|------------|
| **HTTPS/TLS** | 443 | testssl.sh | sslscan / nmap | Media |
| **SSH** | 22 | ssh-audit | nmap / sshpass | Baja |
| **SMTP** | 25, 587, 465 | openssl s_client | nmap | Media |
| **IMAP** | 143, 993 | openssl s_client | nmap | Media |
| **VPN/IPSec** | 500, 4500 | ike-scan | nmap | Alta |
| **RDP** | 3389 | rdpscan | nmap | Media |
| **Base de datos** | 3306, 5432, 1433 | openssl s_client | nmap | Media |

---

## FASE 2 — Análisis de Algoritmos y Fortaleza Criptográfica

### 2.1 Clasificación de cifrados detectados

```bash
# Script para clasificar cifrados detectados
#!/bin/bash
# classify_ciphers.sh

CIPHERS=$(echo | openssl s_client -connect $1:443 2>/dev/null | grep "Cipher" | awk '{print $NF}')

echo "=== ANÁLISIS DE CIFRADOS DETECTADOS ==="
echo ""

for cipher in $CIPHERS; do
    case $cipher in
        # DÉBILES (Rojo)
        *DES* | *RC4* | *MD5* | *SHA1* | *ECB*)
            echo "❌ DÉBIL: $cipher"
            ;;
        # ACEPTABLES (Amarillo)
        *CBC*)
            echo "⚠️  MODERADO: $cipher (CBC requiere análisis adicional)"
            ;;
        # FUERTES (Verde)
        *GCM* | *ChaCha20* | *POLY* | *CTR*)
            echo "✅ FUERTE: $cipher"
            ;;
        *)
            echo "❓ DESCONOCIDO: $cipher"
            ;;
    esac
done
```

### 2.2 Tabla de fortaleza criptográfica

| Cifrado | Tipo | Tamaño Clave | Bloque | Estado | CVSS Riesgo | Acción |
|---------|------|--------------|--------|--------|------------|--------|
| **AES-256-GCM** | Bloque simétrico | 256 bits | 128 bits | ✅ Seguro | Bajo | Mantener |
| **ChaCha20-Poly1305** | Flujo simétrico | 256 bits | N/A | ✅ Seguro | Bajo | Mantener |
| **AES-128-GCM** | Bloque simétrico | 128 bits | 128 bits | ✅ Seguro | Bajo | Mantener |
| **AES-256-CBC** | Bloque simétrico | 256 bits | 128 bits | ⚠️ Aceptable | Medio | Evaluar |
| **3DES-CBC** | Bloque simétrico | 168 bits | 64 bits | ❌ Débil | Alto | ELIMINAR |
| **DES** | Bloque simétrico | 56 bits | 64 bits | ❌ Crítico | Crítico | ELIMINAR URGENTE |
| **RC4** | Flujo simétrico | Variable | 1 byte | ❌ Crítico | Crítico | ELIMINAR URGENTE |
| **MD5** | Hash | N/A | 128 bits | ❌ Crítico | Crítico | CAMBIAR |
| **SHA-1** | Hash | N/A | 160 bits | ❌ Débil | Alto | CAMBIAR |
| **SHA-256** | Hash | N/A | 256 bits | ✅ Seguro | Bajo | Mantener |

### 2.3 Análisis de parámetros Diffie-Hellman

```bash
# Comprobar tamaño de parámetros DH
openssl s_client -connect target.com:443 -tls1_2 2>/dev/null | grep "Server Temp Key"

# Resultados esperados:
# ✅ ECDH (P-384) = Seguro
# ✅ ECDH (X25519) = Seguro
# ⚠️  ECDH (P-256) = Aceptable pero débil
# ❌ DH (1024 bits) = Vulnerable (LogJam CVE-2015-4000)
# ❌ DH (512 bits) = CRÍTICO

# Script de evaluación DH
#!/bin/bash
SIZE=$(echo | openssl s_client -connect $1:443 2>/dev/null | grep "Server Temp Key" | grep -oP '\d+(?= bits)')
if [ $SIZE -lt 1024 ]; then
    echo "❌ CRÍTICO: DH $SIZE bits (Vulnerable a LogJam)"
elif [ $SIZE -lt 2048 ]; then
    echo "⚠️  DÉBIL: DH $SIZE bits"
else
    echo "✅ ACEPTABLE: DH $SIZE bits"
fi
```

---

## FASE 3 — Detección de Cifrados Débiles y Deprecados

### 3.1 Búsqueda de cifrados vulnerables

| CVE | Cifrado Afectado | Versión Vulnerable | CVSS | Descripción | Detección |
|-----|-----------------|-------------------|------|-------------|-----------|
| **CVE-2016-2183** | DES, 3DES en CBC | TLS hasta 1.2 | 6.5 | Sweet32 Birthday Attack | `echo \| openssl s_client -connect target:443 -cipher "DES:3DES"` |
| **CVE-2013-2566** | RC4 | TLS todas | 5.9 | RC4 Biases | `echo \| openssl s_client -connect target:443 -cipher "RC4"` |
| **CVE-2019-9721** | Blowfish en CBC | General | 5.3 | 64-bit block collision | Detectar Blowfish en suite |
| **CVE-2015-4000** | Diffie-Hellman < 1024 | TLS todas | 8.8 | LogJam (precomputed DH) | Tamaño DH < 1024 bits |
| **CVE-2005-0567** | MD5 | Certificados | 5.0 | MD5 colisiones | Certificados con firma MD5 |

### 3.2 Script de detección automática de CVE criptográficos

```bash
#!/bin/bash
# detect_crypto_vuln.sh <target> <port>

TARGET=$1
PORT=${2:-443}

echo "[*] Escaneando $TARGET:$PORT en busca de vulnerabilidades criptográficas"

# Función para comprobar soporte de cifrado
check_cipher() {
    echo | openssl s_client -connect $TARGET:$PORT -cipher "$1" 2>/dev/null | grep -q "Cipher" && return 0 || return 1
}

# CVE-2016-2183 (Sweet32)
if check_cipher "DES:3DES"; then
    echo "❌ CVE-2016-2183 (Sweet32): DES/3DES detectado"
fi

# CVE-2013-2566 (RC4 Biases)
if check_cipher "RC4"; then
    echo "❌ CVE-2013-2566 (RC4 Biases): RC4 detectado"
fi

# Certificado con MD5
openssl s_client -connect $TARGET:$PORT 2>/dev/null | openssl x509 -noout -text | grep -q "md5WithRSAEncryption" && \
    echo "❌ Certificado firmado con MD5 (inseguro desde 2004)"

# DH < 1024 bits (LogJam)
DH_SIZE=$(echo | openssl s_client -connect $TARGET:$PORT 2>/dev/null | grep "Server Temp Key" | grep -oP '\d+')
if [ ! -z "$DH_SIZE" ] && [ "$DH_SIZE" -lt 1024 ]; then
    echo "⚠️  CVE-2015-4000 (LogJam): DH $DH_SIZE bits (< 1024)"
fi

# TLS 1.0 / 1.1 (deprecados)
if echo | openssl s_client -connect $TARGET:$PORT -tls1 2>/dev/null | grep -q "Protocol.*TLSv1"; then
    echo "❌ TLS 1.0 detectado (DEPRECADO)"
fi

if echo | openssl s_client -connect $TARGET:$PORT -tls1_1 2>/dev/null | grep -q "Protocol.*TLSv1.1"; then
    echo "❌ TLS 1.1 detectado (DEPRECADO)"
fi

echo ""
echo "[✓] Auditoría completada"
```

### 3.3 Auditoría en SSH

```bash
#!/bin/bash
# detect_ssh_weak_ciphers.sh

TARGET=$1

echo "[*] Auditando SSH en $TARGET"

# Obtener cifrados ofrecidos
CIPHERS=$(ssh -Q cipher $TARGET 2>/dev/null)

echo "[*] Cifrados detectados:"
for cipher in $CIPHERS; do
    case $cipher in
        3des* | des* | rc4*)
            echo "❌ DÉBIL: $cipher"
            ;;
        aes*cbc*)
            echo "⚠️  MODERADO: $cipher (CBC)"
            ;;
        *gcm* | *ctr* | chacha20*)
            echo "✅ FUERTE: $cipher"
            ;;
        *)
            echo "❓ $cipher"
            ;;
    esac
done

# Cifrado MAC débil
echo ""
echo "[*] Algoritmos MAC detectados:"
MACS=$(ssh -Q mac $TARGET 2>/dev/null)
for mac in $MACS; do
    case $mac in
        md5* | sha1*)
            echo "❌ DÉBIL: $mac"
            ;;
        sha2-512* | sha2-256*)
            echo "✅ FUERTE: $mac"
            ;;
    esac
done
```

---

## FASE 4 — Explotación de Vulnerabilidades Criptográficas

### 4.1 Sweet32 Attack (CVE-2016-2183) — DES/3DES en CBC

**Condiciones:**
- Servidor ofrece DES o 3DES en TLS
- Modo CBC
- Mucho tráfico requerido (~2³⁰ bloques = 34 GB)

```bash
# 1. Confirmar vulnerabilidad
echo | openssl s_client -connect target.com:443 -cipher "DES:3DES" 2>/dev/null

# 2. Capturar tráfico prolongado
tcpdump -i eth0 -w capture.pcap -s 0 "host target.com and port 443"

# 3. Análisis de tráfico (req. tools externas)
# Nota: explotación práctica requiere patrones de datos repetidos + tiempo prolongado
```

### 4.2 LogJam Attack (CVE-2015-4000) — Diffie-Hellman débil

**Condiciones:**
- Servidor soporta parámetros DH < 1024 bits
- TLS 1.2 o anterior

```bash
# 1. Detectar parámetro DH débil
echo | openssl s_client -connect target.com:443 2>/dev/null | grep "Server Temp Key"

# 2. Si es DH < 1024, vulnerable a LogJam
# Explotación: requiere precomputed DH table (fuera de alcance manual)

# 3. Mitigation: forzar ECDHE
echo | openssl s_client -connect target.com:443 -cipher "ECDHE" 2>/dev/null
```

### 4.3 Downgrade Attack — Fuerza servidores a usar cifrados débiles

```bash
# Intenta forzar protocolo débil
echo | openssl s_client -connect target.com:443 -ssl3 2>/dev/null   # SSLv3 (deprecado)
echo | openssl s_client -connect target.com:443 -tls1 2>/dev/null    # TLS 1.0 (deprecado)

# Si responde, vulnerable a downgrade
```

### 4.4 Ataque de timing/side-channel en criptografía

```bash
#!/bin/bash
# timing_attack.sh - detectar timing differentials en implementación criptográfica

# Test básico: comparar tiempos de respuesta
# (requiere herramientas especializadas, aquí pseudocódigo)

for attempt in {1..1000}; do
    time (echo "test-$RANDOM" | openssl enc -aes-256-cbc -S 00 -P -pass pass:"$attempt" > /dev/null)
done | sort -n | head -10

# Análisis: si hay diferencias significativas en tiempos, posible vulnerability
```

---

## FASE 5 — Generación de Claves Seguras

### 5.1 Generar pares de claves criptográficas seguras

```bash
# RSA 4096 bits (recomendado)
openssl genrsa -out private_key.pem 4096
openssl rsa -in private_key.pem -pubout -out public_key.pem

# ECDSA con P-384 (más seguro, más rápido)
openssl ecparam -name secp384r1 -genkey -noout -out ec_private_key.pem
openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem

# Ed25519 (recomendado para SSH/TLS moderno)
ssh-keygen -t ed25519 -C "comment" -f id_ed25519

# X25519 (Diffie-Hellman)
openssl genpkey -algorithm X25519 -out x25519_key.pem

# Generar certificado auto-firmado seguro
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=HackingySeg/CN=target.com"
```

### 5.2 Generar claves simétricas (AES)

```bash
# AES-256 random key (32 bytes)
openssl rand -hex 32 > aes.key

# Encriptar archivo con AES-256-GCM
openssl enc -aes-256-gcm -in plaintext.txt -out encrypted.bin -K $(xxd -p < aes.key) -P

# Desencriptar
openssl enc -d -aes-256-gcm -in encrypted.bin -K $(xxd -p < aes.key)
```

### 5.3 Derivación segura de claves (PBKDF2)

```bash
# Derivar clave de contraseña (16 bits salt, 100,000 iteraciones)
openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password \
    -kdfopt salt:00112233445566778899aabbccddee -kdfopt iter:100000 PBKDF2

# Con password en archivo
openssl enc -aes-256-cbc -S 00112233445566778899 -in plaintext.txt -out encrypted.bin \
    -pass pass:$(cat password.txt) -P -md sha256
```

---

## FASE 6 — Análisis de Certificados Digitales

### 6.1 Extraer y analizar certificados

```bash
# Obtener certificado del servidor
openssl s_client -connect target.com:443 -showcerts 2>/dev/null | tee certs.txt

# Extraer certificado en formato PEM
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -outform PEM > server_cert.pem

# Ver detalles completos del certificado
openssl x509 -in server_cert.pem -text -noout

# Comprobar algoritmo de firma (DEBE ser SHA256, NO MD5/SHA1)
openssl x509 -in server_cert.pem -text -noout | grep "Signature algorithm"

# Verificar cadena de certificados
openssl verify -CAfile ca_bundle.pem server_cert.pem

# Comprobar expiración
openssl x509 -in server_cert.pem -noout -dates
```

### 6.2 Generar CSR (Certificate Signing Request)

```bash
# Generar clave privada
openssl genrsa -out server.key 4096

# Crear CSR con algoritmo seguro (SHA-256)
openssl req -new -key server.key -out server.csr \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=HackingSeg/CN=target.com"

# Verificar CSR
openssl req -in server.csr -text -noout
```

### 6.3 Tabla de análisis de certificados

| Campo | Recomendación | Riesgo si no cumple |
|-------|---|---|
| **Algoritmo de firma** | SHA-256 o superior | ❌ Colisiones MD5/SHA-1 |
| **Tamaño de clave RSA** | >= 2048 bits | ❌ Fuerza bruta (< 2048) |
| **Tipo de curva (ECDSA)** | P-384, P-521 | ⚠️ P-256 débil |
| **Extensiones críticas** | Validadas | ❌ Bypass si no validadas |
| **CN/SANs** | Coinciden con FQDN | ❌ MITM vía CN diferente |
| **Validez** | < 1 año | ⚠️ Exposición prolongada |
| **Datos de Issuer** | CA conocida | ❌ Auto-firmado o CA no confiable |

---

## FASE 7 — Hardening Criptográfico

### 7.1 Configuración segura de TLS en nginx

```nginx
# /etc/nginx/ssl.conf
# Basado en: https://ssl-config.mozilla.org/ (Modern)

ssl_protocols TLSv1.3;  # Solo TLS 1.3
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;

ssl_certificate /etc/ssl/certs/server.crt;
ssl_certificate_key /etc/ssl/private/server.key;

ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### 7.2 Configuración segura de OpenSSH (sshd_config)

```bash
# /etc/ssh/sshd_config

# Protocolos
Protocol 2
Port 22

# Autenticación
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no

# Cifrados (TLS 1.3 style = solo AEAD)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Intercambio de claves
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384

# MAC
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Host keys (solo Ed25519)
HostKey /etc/ssh/ssh_host_ed25519_key

# Security
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxStartups 10:30:100

# Logeo
SyslogFacility AUTH
LogLevel VERBOSE
```

### 7.3 Checklist de hardening criptográfico

```bash
#!/bin/bash
# crypto_hardening_check.sh

echo "=== CHECKLIST HARDENING CRIPTOGRÁFICO ==="

# TLS
echo "[*] Verificando TLS..."
[ $(echo | openssl s_client -connect localhost:443 -tls1 2>/dev/null | wc -l) -eq 0 ] && \
    echo "✅ TLS 1.0 DESHABILITADO" || echo "❌ TLS 1.0 ACTIVO"

# SSH
echo "[*] Verificando SSH..."
grep -q "^Ciphers.*chacha20\|.*aes.*gcm" /etc/ssh/sshd_config && \
    echo "✅ Cifrados SSH fuertes configurados" || echo "❌ Cifrados SSH débiles"

# Certificados
echo "[*] Verificando certificados..."
openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep -q "sha256WithRSAEncryption" && \
    echo "✅ Certificado con SHA-256" || echo "❌ Certificado con algoritmo débil"

# Claves privadas
echo "[*] Verificando permisos de claves privadas..."
[ $(stat -c "%a" /etc/ssl/private/server.key) == "400" ] && \
    echo "✅ Permisos correctos (400)" || echo "❌ Permisos inseguros"

echo ""
echo "[✓] Checklist completado"
```

---

## FASE 8 — Documentación de Hallazgos

### 8.1 Plantilla de hallazgo criptográfico para informe

```
═══════════════════════════════════════════════════════════════════

HALLAZGO: [Nombre completo de la debilidad criptográfica]

SEVERIDAD:    [CRÍTICA/ALTA/MEDIA/BAJA]
CVSS v3.1:    [3.5] (ejemplo)
Vector CVSS:  [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]

SERVICIO:     [TLS/SSH/SMTP]
ENDPOINT:     [target.com:443]
HOSTNAME:     [CN del certificado]
VERSIÓN:      [OpenSSH 8.5p1 / nginx 1.20 / etc]

═══════════════════════════════════════════════════════════════════

DESCRIPCIÓN TÉCNICA:
[Explicación clara del problema, por qué es vulnerable, impacto potencial]

Ejemplo:
El servidor OpenSSH soporta el algoritmo de cifrado "aes128-cbc" que,
aunque teóricamente seguro en AES, el modo CBC en SSH es vulnerable
a timing attacks y requiere verificación de integridad adicional (MAC).
En 2016, se descubrió CVE-2016-2183 (Sweet32) afectando a cifrados
con bloques de 64 bits.

═══════════════════════════════════════════════════════════════════

EVIDENCIA / POC:

$ ssh -vvv usuario@target.com 2>&1 | grep "encryption_algorithms"
debug1: Offering public key authentication
...

Cifrados detectados:
- aes256-ctr           ✅ Seguro
- aes128-cbc           ⚠️  Débil (usar solo como fallback)
- 3des-cbc             ❌ NUNCA

═══════════════════════════════════════════════════════════════════

IMPACTO:

- CONFIDENCIALIDAD:  [COMPROMETIDA / EN RIESGO / ACEPTABLE]
- INTEGRIDAD:        [COMPROMETIDA / EN RIESGO / ACEPTABLE]
- DISPONIBILIDAD:    [COMPROMETIDA / EN RIESGO / ACEPTABLE]

Escenario de explotación:
1. Atacante próximo a la red (MiTM)
2. Captura 2³⁰ bloques de tráfico (~34 GB)
3. Aplica ataque de birthday en DES/3DES
4. Recupera clave de sesión
5. Descifra comunicaciones históricas

═══════════════════════════════════════════════════════════════════

REFERENCIAS:

- CVE-2016-2183 (Sweet32): https://nvd.nist.gov/vuln/detail/CVE-2016-2183
- OWASP A02:2021 Cryptographic Failures:
  https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- RFC 7539 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc7539
- NIST SP 800-38D (GCM): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

═══════════════════════════════════════════════════════════════════

REMEDIACIÓN:

[ ] URGENTE (0-7 días):
    - Deshabilitar cifrados débiles: 3DES, DES, RC4
    - Forzar solo TLS 1.3 si es posible (o TLS 1.2 como mínimo)
    - Actualizar certificados con SHA-256 o superior
    
    Configuración nginx:
    ssl_protocols TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384;
    
    Configuración OpenSSH:
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

[ ] IMPORTANTE (1-2 semanas):
    - Auditar toda la suite criptográfica
    - Regenerar claves de corta vida (< 1 año)
    - Implementar HSTS / preload en navegadores

[ ] MONITOREO (continuo):
    - Ejecutar auditoría criptográfica trimestral
    - Usar testssl.sh en CI/CD
    - Monitorear NVD para nuevos CVE

═══════════════════════════════════════════════════════════════════

VALIDACIÓN POST-REMEDIACIÓN:

$ echo | openssl s_client -connect target.com:443 2>/dev/null | grep Cipher
Cipher : TLS_CHACHA20_POLY1305_SHA256   ✅ CORRECTO

$ openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep "Signature algorithm"
Signature algorithm: sha256WithRSAEncryption   ✅ CORRECTO

═══════════════════════════════════════════════════════════════════
```

### 8.2 Tabla resumen para ejecutivo

| Hallazgo | Severidad | Estado | Acción Requerida |
|----------|-----------|--------|------------------|
| DES/3DES soportados | 🔴 Crítica | Activo | Eliminar en 7 días |
| AES-CBC sin EtM | 🟡 Media | Activo | Cambiar a GCM en 2 sem. |
| Certificado MD5 | 🔴 Crítica | Vencido | Regenerar inmediatamente |
| TLS 1.0 habilitado | 🟡 Media | Activo | Deshabilitar en 7 días |
| ChaCha20 no disponible | 🟢 Baja | Recomendación | Añadir cuando actualizar |

---

## FASE 9 — Referencias y Herramientas

### Herramientas indispensables

```bash
# Instalación en Kali Linux
apt update
apt install -y openssl openssl-tool sslscan testssl.sh ssh-audit nmap

# Python tools
pip install cryptography pycryptodome paramiko requests --break-system-packages

# Desde GitHub
git clone https://github.com/drwetter/testssl.sh.git
git clone https://github.com/PolyCore/ssh-audit.git
```

### Estándares y referencias

| Documento | Descripción | URL |
|-----------|-----------|-----|
| **NIST FIPS 197** | Estándar AES | https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf |
| **RFC 7539** | ChaCha20-Poly1305 | https://tools.ietf.org/html/rfc7539 |
| **RFC 8446** | TLS 1.3 | https://tools.ietf.org/html/rfc8446 |
| **NIST SP 800-175B** | Recomendaciones criptográficas | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf |
| **OWASP A02:2021** | Cryptographic Failures | https://owasp.org/Top10/A02_2021-Cryptographic_Failures/ |

### Bases de datos de vulnerabilidades

- **NVD (National Vulnerability Database):** https://nvd.nist.gov/
- **CVE Details:** https://www.cvedetails.com/
- **SSL Labs:** https://www.ssllabs.com/

---

## INSTALACIÓN RÁPIDA (Kali Linux)

```bash
# Clonar repositorio
git clone https://github.com/hackingyseguridad/cifrados.git
cd cifrados

# Instalar dependencias
apt update
apt install -y openssl openssl-tools sslscan nmap ssh-audit

# testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
chmod +x testssl.sh

# Python dependencies
pip install cryptography paramiko --break-system-packages
```

---

## PLANTILLA DE AUDITORÍA RÁPIDA

```bash
#!/bin/bash
# quick_crypto_audit.sh — Auditoría completa en 5 minutos

TARGET=${1:-target.com}
PORT=${2:-443}

echo "╔════════════════════════════════════════════════╗"
echo "║  AUDITORÍA CRIPTOGRÁFICA RÁPIDA                ║"
echo "║  Target: $TARGET:$PORT                     ║"
echo "║  Fecha: $(date)                    ║"
echo "╚════════════════════════════════════════════════╝"

echo ""
echo "[1/4] Protocolos TLS detectados..."
echo | openssl s_client -connect $TARGET:$PORT -tls1_2 2>/dev/null | grep "Protocol" | head -1
echo | openssl s_client -connect $TARGET:$PORT -tls1_3 2>/dev/null | grep "Protocol" | head -1

echo ""
echo "[2/4] Cifrados ofrecidos..."
echo | openssl s_client -connect $TARGET:$PORT 2>/dev/null | grep "Cipher"

echo ""
echo "[3/4] Información del certificado..."
echo | openssl s_client -connect $TARGET:$PORT 2>/dev/null | openssl x509 -noout -text | \
    grep -E "Subject:|Issuer:|Signature algorithm|Not Before|Not After"

echo ""
echo "[4/4] Parámetros Diffie-Hellman..."
echo | openssl s_client -connect $TARGET:$PORT 2>/dev/null | grep "Server Temp Key"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  ✓ Auditoría completada                        ║"
echo "╚════════════════════════════════════════════════╝"
```

---

## AVISO LEGAL

⚠️ **IMPORTANTE:** Este skill es únicamente para auditoría criptográfica autorizada en sistemas propios
o con consentimiento explícito del propietario. El acceso no autorizado a sistemas informáticos está
prohibido por la ley.

### Cumplimiento Legal Requerido

**España — Código Penal:**
- Art. 197.1 CP: Acceso sin consentimiento a datos protegidos ✅ Necesita **autorización previa**
- Art. 197.2 CP: Divulgación de datos protegidos = 1-4 años prisión
- Art. 198 CP: Acceso fraudulento a sistemas = 6 meses-2 años prisión

**Unión Europea:**
- RGPD (2016/679): Protección de datos + cifrado obligatorio (Arts. 32-34)
- Directiva NIS 2 (2022/2555): Seguridad de infraestructura crítica

**Requisitos previos a cualquier auditoría:**
1. ✅ Contrato de pentest firmado
2. ✅ Autorización escrita explícita del propietario/CTO
3. ✅ Alcance definido (sistemas, IPs, fechas, horarios)
4. ✅ Plan de remediación acordado
5. ✅ Confidencialidad asegurada (NDA)

---

## REFERENCIAS

- **Repositorio:** https://github.com/hackingyseguridad/cifrados
- **Documentación completa:** https://github.com/hackingyseguridad/cifrados/blob/main/cifrados.md
- **Web:** https://www.hackingyseguridad.com

**Autor:** @antonio_taboada | **Licencia:** GPL-3.0  
**Versión:** 2.1 | **Última actualización:** enero 2026

---
