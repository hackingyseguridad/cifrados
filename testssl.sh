#!/bin/sh
# Script to extract IPs and vulnerable ciphers from Nmap SSL scan results
#
# http://www.hackingyseguridad.com/
#
#
#
echo "..."
echo

cat << "INFO"

░░░░░░███████ ]▄▄▄▄▄▄▄▄▃   . . .   http://www.hackingyseguridad.com/
▂▄▅█████████▅▄▃▂
I███████████████████].
◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤

INFO
if [ -z "$1" ]; then
        echo
        echo "Escanea y estrae los cifrados ofrecidos /permitidos"
        echo "Requiere nmap"
        echo "Uso.: sh scan.sh <ip/rango>"
        echo
        exit 0
fi
nmap -v0  $1 $2 --script=ssl-enum-ciphers -sTV --open -oN resultado.txt
echo "cifrados debiles"
echo "SSLv2 TLS1.0 DH EXPORT LOW DES 3DES DHE RC4 MD5 SHA CBC RSA"
echo "==========================================================="

current_ip=""
vulnerable_found=0
while read line; do
  case "$line" in
    "Nmap scan report for "*)
      if [ $vulnerable_found -eq 1 ]; then
        echo ""
      fi
      current_ip="$line"
      vulnerable_found=0
      ;;
    *)
      case "$line" in
         *SSLv2*|*SSLv3|*TLSv1.0*|*TLSv1.1*|*TLSv1.2*|*EXPORT*|*LOW*|*DES*|*RC4*|*_MD5*|*SWEET32*|*3DES*|*_DH*|*_DHE_*|*TLS_DHE_NULL_*|*_anon_*|*_RC2_*)
          if [ $vulnerable_found -eq 0 ]; then
            echo "$current_ip"
            vulnerable_found=1
          fi
          echo "  $line"
          ;;
      esac
      ;;
  esac
done < "resultado.txt"

if [ $vulnerable_found -eq 1 ]; then
  echo ""
fi

exit 0

