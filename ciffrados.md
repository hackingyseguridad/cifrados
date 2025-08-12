Cifrados recomendados
 
## INTRODUCCIÓN

Se analizan los protocolos y cifrados rotos/vulnerados y se elabora un documento que sirva de referencia con los cifrados recomendados con: nivel de seguridad media y nivel de seguridad alta.

## SSL/TLS 

Procolos SSL/TLS; SSL (Secure Sockets Layer) Capa de Conexiones Seguras. Es un protocolo que hace uso de certificados digitales para establecer comunicaciones seguras a través de Internet y utiliza un paquete de cifrados “Cipher Suite”.

### PROTOCOLOS RECOMENDADOS:

SSLv1 = no recomendado, los cifrados están todos rotos/vulnerados. 

SSLv2 = no recomendado, los cifrados están todos rotos/vulnerados.

SSLv3 = no recomendado, los cifrados están todos rotos/vulnerados. ¡Vulnerable a POODLE!

TLS1.0 = no recomendados, porque tienen vulnerabilidades propias el protocolo tls1.0 como BEAST (Browser Exploit Against SSL/TLS), aunque la suite tiene cifrados de trasporte como AES

TLS1.1 = no recomendados, decretado obsoleto el 13/01/2021. Deshabilitado de los Windows en 2023

**TLS1.2 = si es recomendado, con cifrados: AES > 128 GCM y o CHACHA20+POLY1305 256**

**TLS1.3 = si es recomendado, con la suite de cifrados actuales que ofrece.**

### CIFRADOS NO RECOMENDADOS, EN SUITE TLS U OTROS PROTOCOLOS:

Los cifrados y combinaciones recomendadas para los protocolos SSLv2, SSv3, TLS 1.0, TLS 1.1, TLS 1.2 y TLS 1.3, serían los mismos en caso de implementar o configurar cifrado en protocolos como por ejemplo:  SNMPv3, Telnet, sFTP, NFS, smtp, pop3, IMAP4, HTTPs WWW, ...

SSLV2, SSLV3, TLS 1.0, TLS 1.1, TLS 1.2; algoritmos criptográficos y Hash; Longitudes de clave (bits) Seguridad baja, rotos, vulnerables: **no utilizar:**
				
DES	40, 56

CAMELLIA	128

CAST

EXPORT	40

RC2

RC5

RC6

IDEA

SERPENT	

FORTEZZA

TWIFISH

GOST	256

PSK

NULL sin cifrado

UNDEFINED

TLS1.2
				
3DES 	128, 192

ARIA	128, 256

RC4 o ARC4 	 64-2048

AES-ECB	128, 192, 256

AES-CBC	128, 192, 256

AES-CFB	128, 192, 256

AES-CTR	128, 192, 256, 1024	Cifrado	1024, ≥ 128	≥ 256

AES-CCM	128, 192, 256	Cifrado e Integridad	≥ 128	≥ 256

AES-CCM8	128, 192, 256	Cifrado e Integridad	≥ 128	≥ 256

AEAD	128, 192, 256	Integridad	≥ 128	≥ 256

RSA	1024, 2048, 3072, 4096	Intercambio de clave o Firma 	

DH	1024, 2048, 3072, 4096	Intercambio de clave	

ECDH	256, 384, 512	Intercambio de clave	≥ 256	≥ 384

ECDSA	256, 384, 512	Firma	≥ 256	≥ 384

MD5	128	Hash	

SHA-1	160	Hash	

SHA-2 	256, 384, 512	Hash, Hmac	≥  256	≥  384

SHA-3	224, 256, 384, 512	Hash, Hmac	≥  224	≥  384

(ECH)  Encrypted ClientHello  https://blog.cloudflare.com/es-es/encrypted-client-hello-es-es/ nuevo es-tándar que completa a TLS 1.3, el sistema de cifrado que usan las webs HTTPS. Sin ECH, aunque una web esté cifrada, el nombre del dominio al que se accede se transmite en texto plano en el campo SNI, de forma que un intermediario puede saber dónde está navegando el usuario. - el SNI muestra al inicio de la conxexión el fqdn sin cifrar; Sin ECH, aunque una web esté cifrada, el nombre del dominio al que se accede se transmite en texto plano en el campo SNI, de forma que un intermediario puede saber dónde está navegando el  usua-rio. ECH que impide el funcionamiento de los filtros de bloqueo de webs piratas.  
Por ejemplo haciendo interceptación de tráfico en un PC con tecnicas MiTM, con SNI: 
 
AES en combinación de CBC (Cipher Block Chaining) no garantiza la integridad de los datos. CBC es un cifrado en bloque. Un cifrado de bloque es una función que tomará un bloque de texto sin forma-to (la entrada legible por humanos) de longitud n y una clave, y la usará para producir un bloque de texto cifrado de longitud N. 
AES es el cifrado de bloques más popular en este momento, según lo recomiendan tanto NIST como NSA, opera en bloques de 128 bits con claves de 128, 192 o 256 bits.

El problema aquí es que una función destinada a recibir entradas de 128 bits no cifrará una gran canti-dad de datos en una sola llamada. Cuando se enfrenta a ese problema, la solución intuitiva es simplemente dividir sus datos en múltiples bloques de 128 bits y simplemente llamar a AES con la misma clave en cada uno de ellos.
No es seguro porque los patrones de datos pueden permanecer y servir como base para el análisis. CBC tiene como objetivo resolver esto agregando aleatoriedad a cada llamada al cifrado de bloque aplicando la operación exclusiva o (XOR) a cada bloque de texto sin formato con el bloque de texto cifrado generado previamente (o un vector de inicialización aleatorio, para el primer bloque). El descifrado funciona realizan-do el proceso a la inversa y aplicando XOR a cada texto sin formato generado con el texto cifrado anterior.

Ataques Bit Flipping: Es el proceso de XORing bloques de texto plano con el bloque de texto cifrado anterior durante el descifrado lo que introducirá una vulnerabilidad de integridad de datos. Si echamos un vistazo a la tabla de verdad XOR, podemos ver que cambiar un bit de uno de los textos cifrados cambiará la salida de 0 a 1, o de 1 a 0:
Texto cifra-do	Texto sin forma-to	Produc-ción

Qué usar en lugar de CBC - La forma más segura de evitar este problema es utilizar cifrado autenticado, que garantiza la integridad y la confidencialidad de los datos. Galois/Counter Mode (GCM) es una alternativa popular a CBC que proporciona cifrado autenticado con cifrados de bloque como AES. 

## CIFRADOS POST CUANTICOS 

La computación cuántica representara una amenaza significativa para los sistemas de seguridad actuales. Las computadoras cuánticas, gracias a su capacidad de realizar cálculos exponencialmente más rápidos que las computadoras clásicas, podrían romper de forma rápida algoritmos de cifrado actuales.
RIESGOS: PUNTOS DEBILES:
1.- Diccionarios HASH, se podría comprobar diccionarios con millones de HASES en pocos segundos hasta dar con la palabra cifrada = HASH
2.- La capacidad mayor de cómputo podría facilitar romper cifrados con nuevas vulnerabilidades, por inyec-ción u otras nuevas técnicas que están aún por descubrirse. con la tecnología cuántica se reducirá a segundos, cálculos que ahora requieren años.  Actualmente dependemos de la infraestructura PKI (entidad certificadora CA, certificado digital, clave publica y clave privada, autoridad registro, revocación.), que es la infraestructura que verifica la confianza, está basada en cifrados rotos como RSA o curva elíptica DH; RSA y DH se basan en la basan en la factorización, que requeriría años de cómputo con la tecnología actual. Con computación cuántica será fácilmente romper en poco tiempo, ya que se sabe cómo.  Por ejemplo: 
Algoritmo cuántico Grover (1996), reduce el tiempo para encontrar ciertos elementos, reduce signifi-cativamente la fortaleza de las claves actuales; Es una amenaza para los cifrados simétricos son los que usan la misma clave para cifrar y descifrar; por ej.: AES, DES, 3DES,  o diccionarios Hash en SHA-256.  Lo recomendado es duplicar el tamaño de las claves actuales
Algoritmo cuántico Shor (1994), permite descomponer en factores primos un numero compuesto en tiem-po polinómico; Supone una amenaza para cifrados asimétricos que usan claves públicas (cifrado) y claves privadas(descifrado) una infraestructura PKI: intercambios de clave RSA y curvas elípticas:
 
Intercambio de claves públicas (cifrar) y clave privadas (descifrar) con Infraestructura de clave Publica ó PKI: 

### NUEVAS COMBINACIOJNES DE CIFRADOS POST CUANTICO:
NIST lanza el 13 de agosto de 2024, los primeros estándares de cifrados, post cuánticos, que han sido nor-malizados:
Se estima que en pocos años tendremos ya ordenadores cuánticos, accesibles para los todos los usuarios.
Se crea la necesidad de crear nuevos algoritmos post cuánticos que resistan los ataques con tecnología cuánti-ca, combinados sobre los actuales cifrados utilizados.
 
Se crea nuevas combinaciones para con los cifrados actuales, para mitigar posibles ataques: 
CRYSTAL-KYBER ó ML-KEM (Module Lattice Key-Based Encapsulation Mechanism), meca-nismo de encapsulamiento de claves que permite a dos partes intercambiar una clave secreta com-partida de manera segura ML-KEM, un mecanismo de encapsulación de claves seleccionado para cifrado general, como para acceder a sitios web seguros:  ML-KEM-512, ML-KEM-768, ML-KEM-1024
**ML-KEM (Module Lattice Key Encapsulation Mechanism) o crystal - KYBER**, basada en una estructura compleja o reticulos, se utiliza principalmente para el intercambio seguro de claves encriptadas. Esto significa que si dos disposi-tivos quieren comunicarse de forma segura, pueden usar ML-KEM para generar una clave secreta que solo ellos co-nozcan, y luego usar esa clave para cifrar sus mensajes. Resistencia a ataques cuánticos: . Eficiencia: ML-KEM es relativamente eficiente en términos de tiempo de cálculo y tamaño de clave, lo que lo hace adecuado para su imple-mentación en una amplia variedad de dispositivos. Seguridad: ML-KEM se basa en problemas matemáticos que se consideran difíciles de resolver, incluso para las computadoras cuánticas.
Se integrará en OpenSSH, en la suite cifrados ofrecidas para la versión de TLS 1.X: como firma, intercambio seguro de claves; este proceso permite a dos partes establecer una comunicación segura sin compartir una clave secreta de ante-mano. Esto se hace actualmente mediante algoritmos rotos: Diffie-Hellman, ECDH, RSA, RCC,  Elliptic Curve Digital Signature Algorithm (ECDSA), PBKDF  que utilizan pares de claves: una pública y otra privada, fundamentales para muchos protocolos de seguridad, como TLS, ssh, VPN, …
 
p.ej. TLS 1.x  ( AES_256_CGM +  SHA384 ) Protocolo ( Cifrado y modo + HASH algoritmo ) ; cifrado AES, tamaño cadena HASH 256, modo CGM +  HASH algoritmo SHA384, que hace de control de integridad  - será  ML-KEM-512  - 1024 el que se encargara del intercambio de claves segura, combinado en conjunto con AES-256-GCM
https://csrc.nist.gov/pubs/fips/203/ipd 
CRYSTAL-Dilithium ó ML-DSA (Module Lattice Digital Signature Algorithm),  para firma digital. ML-DSA, un algoritmo basado en red elegido para protocolos de firma digital de propósito general .
**ML-DSA (Module Lattice Digital Signature Algorithm) o Cristal Dilitium**, basada en una estructura compleja o retículos, se utiliza principalmente para la firma digital de documentos. Esto significa que se emplea para:
Autenticar la identidad del firmante: Al firmar un documento digitalmente con ML-DSA, se garantiza que la persona que lo firmó es quien dice ser.
Verificar la integridad del documento: ML-DSA permite verificar si un documento ha sido alterado desde que fue firmado. Esto es fundamental para garantizar la confiabilidad de los documentos digitales.
Firma digital de documentos: Para garantizar la autenticidad, integridad y no repudio de documentos elec-trónicos.
Autenticación de usuarios: Para verificar la identidad de usuarios en sistemas informáticos y aplicaciones.
Protección de software: Para garantizar la integridad del software y evitar la instalación de software malicioso.
Blockchain: Para asegurar la integridad y transparencia de las transacciones en las blockchains.
https://csrc.nist.gov/pubs/fips/204/ipd  

**SPHICIS SLH-DSA ó (Stateless Hash-Based Digital Signature)**, algoritmo de firma digital basado en hash, evita ataques de diccionario HASH. SLH-DSA, un esquema de firma digital basado en hash sin estado.
SLH-DSA, o Stateless Hash-Based Digital Signature Algorithm, o SPHINICS +, basado en HASH,  se utili-za principalmente para la firma digital de documentos, pero con una característica distintiva: no requiere un estado interno. Esto significa que cada firma es independiente de las anteriores, lo que lo hace especialmente útil en situaciones donde:
La seguridad a largo plazo es crucial: SLH-DSA ofrece una mayor resistencia a ataques a largo plazo, ya que cada firma es independiente y no compromete la seguridad de firmas anteriores.
Se requiere una alta eficiencia: Al no requerir un estado interno, SLH-DSA puede ser más eficiente en térmi-nos de tiempo de cálculo y tamaño de clave en ciertas aplicaciones.
Se necesita una alta seguridad en entornos con recursos limitados: SLH-DSA es una buena opción para dis-positivos con recursos limitados, como tarjetas inteligentes o dispositivos IoT.
Para ello falta:
Definición de Suites Cifradas: Se crearán nuevas suites cifradas que incluyan SLH-DSA como opción de fir-ma digital. Estas suites especificarán los algoritmos exactos que se utilizarán para la autenticación, el cifrado y la integridad de los datos.
Actualización de Protocolos: Los protocolos TLS existentes deberán actualizarse para reconocer y soportar las nuevas suites cifradas que incluyen SLH-DSA. Esto requerirá cambios en la negociación de cifrado y en la verificación de firmas.
Implementación en Software y Hardware: Los navegadores, servidores web y otros sistemas que implementen TLS deberán ser actualizados para soportar las nuevas suites cifradas. Esto implica cambios en las bibliotecas criptográficas y en el código de aplicación.
Depliegue Gradual: La adopción de SLH-DSA en TLS será un proceso gradual. Inicialmente, coexistirá con los algoritmos existentes, permitiendo una transición suave. A medida que la confianza en SLH-DSA aumen-te y los sistemas se actualicen, se espera que se convierta en la opción preferida para muchas aplicaciones.
https://csrc.nist.gov/pubs/fips/205/ipd/
Falcon -previsiblemente será validado por el NIST en 2025 como uno de los nuevos estándares de criptogra-fía post cuántica. Esto significa que Falcon está diseñado para resistir los ataques de las futuras computadoras cuánticas, que se espera que sean capaces de romper los sistemas de cifrado actuales con relativa facilidad.
La principal función de Falcon es garantizar la autenticidad y la integridad de los datos digitales. En términos más sencillos, Falcon se utiliza para:
- Firmar digitalmente documentos: Esto permite verificar la identidad del firmante y asegurar que el docu-mento no ha sido alterado desde que se firmó.
- Autenticar transacciones: En el comercio electrónico, Falcon puede utilizarse para verificar la identidad de las partes involucradas en una transacción y garantizar que los datos no hayan sido manipulados.
- Proteger la comunicación: Falcon puede utilizarse para asegurar la confidencialidad de las comunicaciones al garantizar que solo las partes autorizadas puedan acceder a los mensajes.
Estos nuevos algoritmos tienen el objetivo de proteger los datos intercambiados en redes públicas, y las fir-mas digitales que se usan para autentificar las identidades de las personas. Actualmente se usan algoritmos de cifrado como RSA, vulnerado y superado por la computación cuántica.  Impactara a corto plazo, en las im-plementación y nuevos dispositivos o nuevas actualizaciones de sofware-firmware, que veremos en múltiples dispositivos.
https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards 
https://csrc.nist.gov/Projects/Post-Quantum-Cryptography 
https://pq-crystals.org/ 
https://es.wikipedia.org/wiki/Criptograf%C3%ADa_postcu%C3%A1ntica 

## CONJUNTO DE COMBINACIONES (CIPHER SUITE) RECOMENDADAS TLS
Ejemplos de combinaciones TLS, recomendadas:  La combinación de: Intercambio de clave + firma + cifra-dos y tamaño de HASH > 128 + curva elíptica, hacen que un conjunto de cifrados (cipher suite) sea conside-rado segura!, lo que por sí solos o conjunto de dos, no lo son; (Se incluyen por ejemplo, los cifrados no re-comendaos “por si solos” ARIA y CAMELIA que si van acompañados de _GCM_ o _POLY1305 sí serian seguros! ):

[seguridad_alta.txt](https://github.com/hackingyseguridad/cifrados/blob/main/seguridad_alta.txt)

Combinación AES-256-CMAC
MACsec (Seguridad de control de acceso a medios): Este protocolo aprovecha AES-256-CMAC para la verificación del origen de los datos y el cifrado en redes cableadas. Se podría combinar con otros algorit-mos como GCM (Galois/Counter Mode) para funciones de cifrado adicionales.
Seguridad de pagos: Algunos sistemas de pago podrían utilizar AES-256 para el cifrado de datos y CMAC para la autenticación de mensajes, pero a menudo junto con otras medidas de seguridad como proto-colos de gestión de claves.
En general, AES-256-CMAC es una combinación sólida para la seguridad de los datos, pero es un bloque de construcción más que una suite completa. Su uso a menudo depende de la aplicación específica y podría im-plementarse con algoritmos adicionales para una solución de seguridad más completa.
AES-256-CMAC es una combinación sólida para la seguridad de los datos, pero es un bloque de construc-ción más que una suite completa. Su uso a menudo depende de la aplicación específica y podría implementar-se con algoritmos adicionales para una solución de seguridad más completa.

Diffie-Hellman
Además de CVE-2022-20001 y los ataques Logjam, DHEAT ATTACK existen otras vulnerabilidades públicas que han explotado debilidades en el protocolo Diffie-Hellman (DH) o en su implementación:

Vulnerabilidades en Bibliotecas Criptográficas
Heartbleed: Aunque principalmente asociado con OpenSSL, esta vulnerabilidad también podía afectar a implementaciones de DH en otras bibliotecas. Permitió a atacantes leer grandes cantidades de memoria del servidor, incluyendo claves privadas.
DROWN: Esta vulnerabilidad explotaba la reutilización de claves SSL/TLS en combinación con pro-tocolos vulnerables como SSLv2. Al aprovechar esta debilidad, los atacantes podían descifrar sesiones SSL/TLS protegidas con DH.

Ataques de Canal Lateral Específicos para DH
Ataques de timing: Estos ataques miden el tiempo que tarda un dispositivo en realizar ciertas opera-ciones criptográficas para inferir información sobre la clave secreta.
Ataques de potencia: Al medir el consumo de energía de un dispositivo durante el cálculo de DH, los atacantes pueden obtener información sobre la clave secreta.
Ataques de caché: Estos ataques aprovechan las características de las cachés de procesador para infe-rir información sobre la clave secreta.

Vulnerabilidades Relacionadas con la Configuración
Uso de grupos DH débiles: La elección de grupos DH demasiado pequeños o con propiedades ma-temáticas débiles puede facilitar ataques de fuerza bruta.
Falta de validación de parámetros: Si no se valida correctamente la entrada del usuario, los atacantes pueden proporcionar parámetros maliciosos que permitan ataques.
Implementaciones inseguras de ECDH: El Elliptic Curve Diffie-Hellman (ECDH) es una variante de DH basada en curvas elípticas. Vulnerabilidades en su implementación pueden permitir ataques similares a los de DH.

## CONJUNTO DE CIFRADOS (CIPHER SUITE) NO RECOMENDADOS TLS

[seguridad_media.txt](https://github.com/hackingyseguridad/cifrados/blob/main/seguridad_media.txt)

seguridad_baja.txt

3.	IPSEC
IPSec es un “conjunto de protocolos”: Protocolo 51 AH: (Integridad y autentificación).  y/ó Protocolo 50 ESP (En-capsulación): 
 
Tunel: Datos de usuario se enviarán a través del túnel IKE fase 
 
IKE construye los túneles para nosotros, pero no autentica ni cifra los datos del usuario. Usamos otros dos protocolos para esto: AH (Encabezado de autenticación) ESP (carga útil de seguridad encapsulada) AH y ESP ofrecen autentica-ción e integridad, pero solo ESP admite el cifrado!
 
3.1	IKE V1
NO UTILIZAR   

3.2	IKE V2  
  IKEv2:

1.	Cifrados recomendados y tamaño de hash:  AES ≥ 256, SHA-2 ≥  512  - No utilizar cifrados rotos: 3DES, MD5, RC4, SHA-1, RSA… (ver Tabla cifrados recomendados )
2.	Grupos DH Diffie-Hellman 

Grupo Diffie-Hellman 2 - módulo de 1024 bits -   EVITAR
Grupo Diffie-Hellman 5 - módulo de 1024 bits -   EVITAR
Grupo Diffie-Hellman 14 - módulo de 2048 bits - ACEPTABLE
Grupo Diffie-Hellman 24: - ACEPTABLE
Grupo Diffie-Hellman 19 - 256 bits curva eliptica –  RECOMENDADO
Grupo Diffie-Hellman 20 - 384 bits curva eliptica –  RECOMENDADO
Grupo Diffie-Hellman 21 - 512 bits curva eliptica –  RECOMENDADO
https://safecurves.cr.yp.to/ 
https://nvd.nist.gov/vuln/detail/CVE-2002-20001 

3.	 Configuración propuesta “sin tener en cuenta incompatibilidades o rendimiento”:
!crypto ikev2 policy 10
encryption aes-256
integrity sha512
group 21
!
4.	Importante también en la configuración es establecer Timeout: Tiempo de desconexión y volumen de tráfico: LifeTime: Time:10:0:0, Traffic Volumen: 36000
4.	SSH/ SCP
SSH protocolo y programa que lo implementa cuya principal función es el acceso remoto a un servidor por medio de un canal seguro en el que toda la información está cifrada. Además de la conexión a otros dispositivos.
 
4.1	SSH V1  
NO UTILIZAR:
4.2	SSH V2 
Para SSH v2 por y para simplificar, como elemento principal de criterio utilizaremos fundamentalmente el cifrado de tras-porte (encryption_algoritms).

SSH 2
|   kex_algorithms: (10)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|       diffie-hellman-group14-sha1
|   … mínimo diffie-hellman-group14, modulo 2048
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa 
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (17)
|       aes256-gcm
|       aes192-gcm
|       aes128-gcm
|       aes256-ctr
|       aes192-ctr
|       aes128-ctr
|       chacha20-poly1305@openssh.com
|       sha-1
|       md5
|       DES
|       3des-cbc
|       arcfour (RC4)
|       arcfour128 (RC4 128)
|       arcfour256 (RC4 256)
|       blowfish-cbc
|       cast128-cbc
|
|   mac_algorithms: (12)
|       hmac-md5
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|       SM3 HMAC algorithm
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com

RECOMENDADOS: Cifrados de trasporte (encryption_algoritms): seguridad media: aes-128-xxx, aes-192-xxx, seguri-dad alta: aes-256-xxx,  CHACHA20+POLY1305. ( AES = también llamado Rijndael )

(server_host_key_algorithms), eliminar de la configuración RSA, como cifrado para la clave, y ofrecer por ejemplo como alternativas las combinaciones: rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519
https://www.endpointdev.com/blog/2023/04/ssh-host-key/# 

NO UTILIZAR: RSA, DSA, DES, 3des, MD5, blowfish, RC4.

key_algorithms, server_host_key_algorithms, mac_algorithms, compression_algorithms “sería poco relevantes” los ahí ofrecidos siempre y cuando los cifrados de trasporte(encryption_algorithms) permitidos sea los recomendados.

Desde la versión OpenSSH  8.8, el algoritmo de clave ssh-rsa ha sido deshabilitado. En versiones anteriores, podemos deactivarlo a mano, editando en el fichero /etc/ssh/sshd_config, y eliminando de Host KeyAlgorithms +ssh-rsa:

mac_algorithms: () recomendados hmac. Para evitar incidencias de clientes SSH que no soportan hmac, ofrecer por ahora tambien todas las combinaciones  umac.

5.	PROTOCOLOS DE TRANSFERENCIA DE ARCHIVOS
Protocolos de transferencia de archivos ( ftp ,  SFTP,  FTPS ó FTPES)

FTP es un protocolo obsoleto y a través del cual la información viaja sin cifrar, por lo que puede quedar expuesta. 

FTPES, FTPS y SFTP, son seguros. FTPES, FTPS pues implementa el protocolo TLS, mientras que SFTP se basa en SSH:  

- es importante que en el caso de TLS se ofrezca la versión 1.3 o 1.2 y cifrados recomendados, ya que las anteriores son obsoletas y no son seguras.

- Para SFTP, tendremos en cuenta las recomendaciones para SSH descritas en el Punto 4 ( SSHv2), anterior
6.	PGP/GPG Y  S/MINE
Las capas de cifrado de archivos son protocolos que aprovechan uno (o varios) de los algoritmos para cifrar datos en reposo y en tránsito. Puede "superponer" algoritmos para complementar sus funciones de seguridad o proporcionar seguridad adicional. Por ejemplo, puede usar TLS para cifrar los archivos que está transfiriendo a través de la nube y anular el cifrado PGP en los archivos que está transfiriendo a través de un canal TLS para mayor seguridad.
PGP ofrece cifrado, autenticación de e-mail y comprobación de su integridad. Combinaciones de cifrado recomenda-das en PGP/GPG

Cifrado simétrico (para el mensaje/cuerpo del archivo)
AES-256 (Recomendado)
AES-192 (Buen equilibrio)
AES-128 (Sólido, pero menos resistente a largo plazo)
Evita algoritmos obsoletos como 3DES, CAST5, IDEA o Blowfish.

Algoritmo de intercambio de claves (KEM - Key Encapsulation Mechanism)
ECDH (Curve25519) → Mejor opción actual (basado en curvas elípticas, eficiente y post-cuántico resistente).
DH (Diffie-Hellman) con módulo de 4096 bits → Seguro, pero menos eficiente que ECDH.
DH con 3072 bits → Buen equilibrio entre seguridad y rendimiento.
Evita RSA para el intercambio de claves, ya que es menos eficiente y más vulnerable a largo plazo.

Algoritmo de firma digital (autenticidad e integridad)
EdDSA (Ed25519) → Recomendado (firma rápida y segura).
ECDSA (secp256k1 o secp384r1) → Alternativa sólida.
RSA (4096 bits) → Aún seguro, pero menos eficiente.
Evita RSA < 3072 bits o DSA, ya que son considerados inseguros hoy en día.

NO UTILIZAR: RSA 1024, 2048, DSA, TWOFISH, CAMELLIA128, CAMELLIA192, CAMELLIA256,  IDEA, 3DES, CAST5, BLOWFISH, AES, RSA

RSA está vulnerado. De no tener alternativa, de no tener otra opción, tendría que ser 3072 bits de longitud, mínimo, claves de 4096 bits podría ser la opción más segura. Con la tecnología cuántica deberemos dejar de usarlo. La opción segura es usar al menos 3072 bits (en RSA/DH) o Curve25519/Ed25519 (en ECC). 

S/MIME (Secure / Multipurpose Internet Mail Extensions, del inglés, Extensiones de Correo de Internet de Propósi-tos Múltiples / Seguro) es un estándar para criptografía de clave pública y firmado de correo electrónico encapsulado en MIME. Provee los siguientes servicios de seguridad criptográfica para aplicaciones de mensajería electrónica:
autenticación, integridad y no repudio (mediante el uso de firma digital) y privacidad y seguridad de los datos (mediante el uso de cifrado)
S/MIME especifica el tipo application/pkcs7-mime (tipo smime "enveloped-data") para envoltura de datos (cifrado): la entidad MIME completa a ser envuelta se cifra y se empaca en un objeto que luego se inserta en una entidad MIME application/pkcs7-mime.
La funcionalidad S/MIME está construida en la mayoría de las apps de correo electrónico modernos y son capaces de interoperar entre ellos. Un correo firmado tiene estos encabezados ocultos.

En los próximos años, se espera que PGP/GPG adopte algoritmos resistentes a la computación cuántica, como Kyber (KEM) y Dilithium (firma digital), pero por ahora, ECDH (Curve25519) + EdDSA + AES-256 sigue siendo la mejor opción.
7.	CIFRADOS DE ALMACENAMIENTO DE DATOS
Para almacenamiento de datos en disco o ficheros, utilizaremos los cifrados recomendados AES > 128 y /o las combinaciones:

MD5
3DES 
SHA-1
AES > 128 
AES 1024 CTR
TwoFish
Serpent
AES-Twofish
Serpent-AES
TwoFish-Serpent
AES-Twofish-Serpent
Serpent-Twofish-AES
AES-Twofish-Serpent+SHA512

AES 1024, “seguridad Militar” !!! utilizada para cifrar datos en almacenamientos, memorias y discos duros; Sylvain Pelissier y Bio Sletterink han encontrado una manera de descifrar AES de 1024 bits; Descubrieron que se ha utilizado un método de tipo CTR (Contador) para el cifrado, de solo 128 bits. El elemento básico de las claves para crear una clave de 1024 bits usó el PBKDF2, y luego con la adi-ción de un valor salt y un valor entero una vez que se conoce la contraseña. Luego, el elemento de 1024 bits se crea mediante bloques de cifrado de 128 bits, con la adición de las derivaciones de claves: CVE-2021–36750

8.	WIFI
Por su propia naturaleza inalámbrica las redes wifi están expuestas a todo tipo de ataques remotos que pue-den lanzarse desde equipos situados en las inmediaciones. Pueden ser de intermediario (Man-in-the-Middle) donde el actor malicioso intercepta y altera la comunicación entre router y cliente, de recuperación de clave mediante fuerza bruta y diccionario para averiguar la contraseña de la red, de descifrado del tráfico para leer el contenido de la comunicación y de denegación de servicio, con el fin de sobrecargar la red e interrumpir su normal funcionamiento o expulsar clientes.

Abierta:  No utilizar
WEP.:  No utilizar
WPA.:   No utilizar
WPA2  con opción cifrado AES 128  – No utilizar cifrado TKIP
WPA3  AES 128 ó 256
 
Wifi 6 sería el más seguro con WPA3. 
Wifi 4 y 5 aún se podría usar, pero requiere configuración y cifrados recomendados.

Recomendaciones:
-	Evitar protocolos de cifrado: WEP y WPA-TKIP: obsoletos y fáciles de hackear.
-	Usar WPA3 siempre que esté disponible; es el más seguro actualmente.
-	Desactivar WPS (Wifi Protected Setup): vulnerable a ataques de fuerza bruta.
-	Actualizar el firmware del router: última versión disponible, que corrija vulnerabilidades conocidas como p.ej. KRACK y Dragonblood.

Wifi 4 (802.11n - 2009)

Cifrados; WEP (obsoleto, inseguro). WPA-TKIP (vulnerable). WPA2-AES (recomendado, vulnerable a KRACK).
Vulnerabilidades: 
KRACK Attack (Key Reinstallation Attack) Afecta a WPA2 en dispositivos 802.11n. Permite interceptar y manipular tráfico.
Cifrado TKIP. WPA-TKIP puede ser descifrado con ataques de fuerza bruta.
Falta de protección en bandas de 2.4 GHz y 5 GHz. susceptible a interferencias y ataques de deautenticación.

Wifi 5 (802.11ac - 2014)

Cifrados:
WPA2-AES (predeterminado, vulnerable a KRACK).
WPA3 (soporte opcional, más seguro).
Vulnerabilidades: KRACK Attack . Dragonblood Attack Ataques de deautenticación.

Wi-Fi 6 (802.11ax - 2019)

Cifrados utilizados: WPA3-SAE, WPA3-Enterprise (192-bit AES) (máxima seguridad) Enhanced Open (OWE) para redes públicas.
Vulnerabilidades: Dragonblood Attack. Ataques de canal lateral. DoS por inundación de frames.


9.	RESUMEN DE RECOMENDACIONES
Nº 	 	Ámbito 	Resumen 	TLS 1.2 	TLS 1.3 
1  	 	General 	Usar la versión del protocolo TLS 1.2 o superior. Deshabilitar en el servidor ofrecer las versiones anteriores a TLS 1.2.  	Aplica 	Aplica

2	 	VPN SSL 	Para Sistemas ENS: Utilizar productos Cualificados de la fa-milia Redes Privadas Virtuales SSL dentro del Catálogo de Productos de Seguridad TIC (CPSTIC).  	Aplica 	Aplica
			Para Sistemas que manejen información clasificada: Utilizar productos Aprobados dentro del Catálogo de 		
			Productos de Seguridad TIC (CPSTIC) 		
3	 	Key 
Exchange 	No utilizar claves pre-compartidas (PSK). 	Aplica 	Aplica
4		Key 
Exchange 	Usar DHE o ECDHE.  	Aplica 	No Aplica
			No usar RSA ni DH o ECDH estáticos. 		
5		Key 
Exchange 	Soporte de Curvas Elípticas. 	Aplica 	No Aplica
6		Key 
Exchange 	Soporte de la extensión Supported_Groups. 	Aplica 	No Aplica
7		Autentica-ción Web y SSH	Autenticación Clave ó  key, solp permite conexiones de clien-tes cuya clave coincida con la del servidor. La clave privada se coloca en tu máquina local y la clave pública se carga en el servidor. Usar certificados X.509v3 de tipo RSA o ECDSA.	Aplica	Aplica
8		Firma 	Usar la extensión signature_algorithms. Emplear algoritmos de firma RSA o ECDSA, con funciones SHA-2 o superior. 	Aplica 	No Aplica
9  		Autentica-ción y Firma 	Usar claves públicas con fortaleza superior a 112 bits. Para categoría ALTA del ENS o sistemas clasificados, usar una fortaleza superior a 128 bits (RSA ≥ 3072 bits, ECDSA ≥ 256 bits). 	Aplica 	Aplica
10		Cifrado 	Usar AES en modo GCM 	Aplica 	No Aplica
11		Hash 	Usar funciones hash SHA-2 o superior.  No utilizar SHA-3	Aplica 	No Aplica
12	 	Cipher
Suites 	Hacer uso de alguna de las siguientes cipher suites (TLS 1.2):  

Habilitar HSTS en el servidor web incluir cabecera que fuerce cifrado desde el inicio:
Header always set Strict-Transport-Security «max-age=31536000; includeSubDomains»	Aplica 	No Aplica
			CHACHA20+POLY1305 256		
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 		
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 		
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 		
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 		
13	Certificados 	No utilizar certificados auto-firmados, sino emitidos por una CA de confianza, con flujos OSCP para verificación hacia la PKI	Aplica 	Aplica
14	Certificados 	Usar autenticación mutua entre cliente y servidor TLS, de forma que no solo el servidor proporcione un certificado, sino también el cliente. 	Aplica 	Aplica
15	Certificados 	Implementar validación de certificados según RFC 5280. 	Aplica 	Aplica
16	Certificados 	Implementar verificación del estado de revocación del certi-ficado a través de listas CRLs o protocolo OCSP. 	Aplica 	Aplica
17	Certificados 	Soportar una cadena de, al menos, tres (3) certificados. 	Aplica 	Aplica
18  	Certificados 	Servidor y cliente TLS deben rechazar la conexión TLS cuando el certificado no haya superado el proceso de validación.  	Aplica 	Aplica
18  	Certificados 	Servidor y cliente TLS deben rechazar la conexión TLS cuando no pueda verificarse el estado de revocación del certificado.  	Aplica 	Aplica
		En caso de que el entorno operativo no lo permita, el esta-blecimiento de la conexión deberá ser aprobado por un ad-ministrador. 		
19	Certificados 		Aplica 	Aplica
				

