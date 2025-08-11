
#!/bin/sh

# Verificar si se proporcionó el archivo de resultados
if [ -z "$1" ]; then
    echo "Uso: $0 <archivo_resultados_nmap.txt>"
    echo "Ejemplo: $0 resultado.txt"
    exit 1
fi

ARCHIVO_RESULTADOS=$1
ARCHIVO_FILTRADO="hosts_vulnerables.txt"

# Lista de cifrados débiles a buscar
CIFRADOS_DEBILES="SSLv2 EXPORT LOW DES RC4 MD5 NULL"

# Verificar si el archivo existe
if [ ! -f "$ARCHIVO_RESULTADOS" ]; then
    echo "Error: El archivo $ARCHIVO_RESULTADOS no existe"
    exit 1
fi

echo "Analizando $ARCHIVO_RESULTADOS en busca de cifrados débiles..."
echo "Cifrados débiles buscados: $CIFRADOS_DEBILES"
echo ""

# Procesar el archivo
awk -v cifs="$CIFRADOS_DEBILES" '
BEGIN {
    split(cifs, cifrados, " ")
    host_actual = ""
    vulnerable = 0
    print "Hosts con cifrados débiles encontrados:" > "hosts_vulnerables.txt"
    print "=======================================" > "hosts_vulnerables.txt"
}

# Capturar dirección IP del host
/Nmap scan report for/ {
    host_actual = $5
    vulnerable = 0
}

# Buscar cifrados débiles en las líneas de resultados
/SSLv2|EXPORT|LOW|DES|RC4|MD5|NULL/ {
    for (c in cifrados) {
        if ($0 ~ cifrados[c]) {
            if (!vulnerable) {
                print "\nHost vulnerable: " host_actual >> "hosts_vulnerables.txt"
                vulnerable = 1
            }
            print "  [!] " $0 >> "hosts_vulnerables.txt"
            next
        }
    }
}

END {
    print "\nAnálisis completado. Resultados guardados en hosts_vulnerables.txt"
}
' "$ARCHIVO_RESULTADOS"

# Mostrar resumen
echo ""
echo "Resumen de hosts vulnerables:"
echo "============================="
grep "Host vulnerable:" "$ARCHIVO_FILTRADO" | cut -d' ' -f3- | sort -u
echo ""
echo "Detalles completos en: $ARCHIVO_FILTRADO"
