nmap -iL todas.txt --script=ssl-enum-ciphers  -F -PE -sTV --open -n --randomize-hosts --max-retries 2 --min-rate 1000 
