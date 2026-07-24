#!/bin/bash
# CIFRAR/DESCIFRAR FICHERO V.1.0
# http://www.hackingyseguridad.com

cat << "INFO"
CIFRAR/DESCIFRAR FICHERO V.1.0 
http://www.hackingyseguridad.com
INFO

# Función para mostrar ayuda
mostrar_ayuda() {
    echo
    echo "Uso: $0 -c|-d <fichero>"
    echo "  -c    Cifrar fichero"
    echo "  -d    Descifrar fichero"
    echo "  -h    Mostrar esta ayuda"
    echo
    echo "Ejemplos:"
    echo "  $0 -c archivo.txt     # Cifra archivo.txt -> archivo.txt.enc"
    echo "  $0 -d archivo.txt.enc # Descifra archivo.txt.enc -> archivo.txt.new"
    echo
    exit 0
}

# Verificar que se pasaron argumentos
if [ $# -lt 2 ]; then
    echo
    echo "ERROR: Faltan parámetros"
    mostrar_ayuda
fi

# Obtener la opción y el archivo
OPCION="$1"
ARCHIVO="$2"

# Verificar que el archivo existe
if [ ! -f "$ARCHIVO" ]; then
    echo
    echo "ERROR: El archivo '$ARCHIVO' no existe"
    echo
    exit 1
fi

# Procesar la opción
case "$OPCION" in
    -c)
        echo
        echo "Cifrando el fichero: $ARCHIVO"
        echo
        openssl aes-256-cbc -a -salt -in "$ARCHIVO" -out "$ARCHIVO.enc"
        if [ $? -eq 0 ]; then
            echo
            echo "Cifrado completado. Archivo generado: $ARCHIVO.enc"
            echo
        else
            echo
            echo "ERROR: Falló el cifrado"
            echo
            exit 1
        fi
        ;;
    -d)
        echo
        echo "Descifrando el fichero: $ARCHIVO"
        echo
        openssl aes-256-cbc -d -a -in "$ARCHIVO" -out "$ARCHIVO.new"
        if [ $? -eq 0 ]; then
            echo
            echo "Descifrado completado. Archivo generado: $ARCHIVO.new"
            echo
        else
            echo
            echo "ERROR: Falló el descifrado. Verifica la contraseña."
            echo
            exit 1
        fi
        ;;
    -h|--help)
        mostrar_ayuda
        ;;
    *)
        echo
        echo "ERROR: Opción no válida: $OPCION"
        mostrar_ayuda
        ;;
esac

exit 0
