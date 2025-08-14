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


