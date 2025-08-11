


nmap -iL todas.txt --script=ssl-enum-ciphers  -F -PE -sTV --open -n --randomize-hosts --max-retries 2 --min-rate 1000 

echo "cifrados debiles"
echo "SSLv2  EXPORT LOW  DES  RC4  MD5 NULL" 


