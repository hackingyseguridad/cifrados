#!/bin/sh
# Script to extract IPs and vulnerable ciphers from Nmap SSL scan results
#
# http://www.hackingyseguridad.com/
#
#
nmap -v0 -iL ip.txt -F --script=ssl-enum-ciphers -PE -sTV --open -n --randomize-hosts --max-retries 2 --min-rate 999 -oN resultado.txt
echo "cifrados debiles"
echo "SSLv2  EXPORT LOW  DES  RC4  MD5 NULL"
echo "====================================="

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
        *SSLv2*|*EXPORT*|*LOW*|*DES*|*RC4*|*MD5*|*SWEET32*|*3DES*)
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
