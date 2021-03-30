# QUINT
QUIck INTel - A DNS record request and NMAP wrapper. Easier than having to go to MXToolbox or online WHOIS/WHOISIP sites. This offers no new, exciting, or novel functionality. 

# DEPENDENCIES
1. Python 3.10
   * I use structural pattern matching instead of if statements because I think they look better
2. Nmap
    * Used for some of their NSEs like WHOIS and WHOISIP, Full scans, etc. Not needed if you're just checking MX/A/CNAME/etc records, which queries google's dns. 
4. XMLTODICT
    * Used for converting NMAP's XML output to Json. 
    * pip3 install xmltodict
5. Being able to connect to https://dns.google.
    * Used to check dns records. 

