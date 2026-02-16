# **Cifrados y Protocolos de Seguridad - Guía Actualizada**

## **Importante: Diferenciar entre Encoding y Cifrado**

### **Sistemas de Encoding (NO son cifrado)**
- **Base64**: Sistema de codificación para representar datos binarios en texto ASCII. **No proporciona confidencialidad**.
- **Hexadecimal (Hex)**: Representación de datos binarios en base 16. **No es un cifrado**.
- **URL Encoding**: Codificación de caracteres para su uso en URLs. **No es un cifrado**.

---

## **Algoritmos de Cifrado Simétrico**

### **AES (Advanced Encryption Standard)**
- **Tipo**: Cifrado de bloque
- **Longitudes de clave**: 128, 192 o 256 bits
- **Estado**: Seguro y ampliamente adoptado
- **Modos de operación recomendados**: GCM, CCM (con autenticación)
- **Seguridad**: No es vulnerable a ataques de fuerza bruta con tecnología actual

### **ChaCha20**
- **Tipo**: Cifrado de flujo
- **Longitud de clave**: 256 bits
- **Ventaja**: Alto rendimiento en software
- **Comúnmente usado con**: Poly1305 para autenticación

### **3DES (Triple DES)**
- **Estado**: **OBSOLETO** - Desaprobado por NIST desde 2017
- **Razón**: Longitud de clave efectiva de sólo 112 bits, vulnerable a ataques

### **DES (Data Encryption Standard)**
- **Estado**: **COMPLETAMENTE INSECURE** - Clave de 56 bits, fácilmente vulnerable

---

## **Algoritmos de Cifrado Asimétrico**

### **RSA**
- **Uso principal**: Intercambio de claves y firmas digitales
- **Longitudes recomendadas**: 2048 bits (mínimo), 3072-4096 bits para nueva infraestructura
- **Importante**: No diseñado para cifrar grandes volúmenes de datos directamente

### **ECDSA (Elliptic Curve Digital Signature Algorithm)**
- **Ventaja**: Claves más cortas para misma seguridad que RSA
- **Curvas recomendadas**: P-256, P-384, P-521

### **Diffie-Hellman**
- **Propósito**: Intercambio de claves seguro
- **Versiones**: Ephemeral (ECDHE) recomendado para forward secrecy

---

## **Protocolos de Comunicación Segura**

### **TLS (Transport Layer Security)**
- **Versiones seguras**: TLS 1.2 y TLS 1.3
- **Obsoletos e inseguros**: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
- **Cifrados recomendados**: AES-GCM, ChaCha20-Poly1305

### **SSH (Secure Shell)**
- **Algoritmos recomendados**: 
  - Cifrado: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`
  - KEX: `curve25519-sha256`
  - MAC: `hmac-sha2-512`

---

## **Funciones Hash y Autenticación**

### **SHA-2 Family**
- **Variantes**: SHA-256, SHA-384, SHA-512
- **Estado**: Seguro y recomendado

### **SHA-1**
- **Estado**: **VULNERABLE** - Colisiones prácticas demostradas

### **MD5**
- **Estado**:**COMPLETAMENTE QUEBRADO** - No usar para seguridad

### **HMAC**
- **Propósito**: Autenticación de mensajes
- **Combinaciones recomendadas**: HMAC-SHA256, HMAC-SHA512

---

## **Recomendaciones de Implementación**

### **Principios Esenciales**
1. **Never roll your own crypto**: Usar librerías bien auditadas
2. **Use nonces/IVs únicos**: Nunca reutilizar vectores de inicialización
3. **Authenticated encryption**: Preferir cifrados con autenticación integrada (GCM, CCM)
4. **Proper key management**: Rotación regular de claves, almacenamiento seguro

### **Configuraciones Seguras**
```bash
# Ejemplo configuración TLS moderna (Mozilla Intermediate)
Ciphers: TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
KEX: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
```

---

## **Referencias y Recursos**

### **Estándares Actuales**
- **NIST FIPS 140-3**: Estándar para módulos criptográficos
- **OWASP Cryptographic Storage Cheat Sheet**: Mejores prácticas
- **RFC 8446**: TLS 1.3 specification

### **Herramientas de Análisis**
- **testssl.sh**: Análisis de configuración TLS/SSL
- **sslyze**: Scanner de configuración SSL
- **cipherscan**: Análisis de suites de cifrado

---

## **⚠️ Advertencias de Seguridad**

1. **Los cifrados deben elegirse según el contexto de uso**
2. **La implementación correcta es tan importante como el algoritmo**
3. **Mantener actualizadas las librerías criptográficas**
4. **Realizar auditorías de seguridad periódicas**

---

**Última actualización**: Agosto 2025 - http://www.hackingyseguridad.com
