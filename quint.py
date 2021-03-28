import json
import urllib.request
from re import match
import xmltodict
import os
import argparse

parser = argparse.ArgumentParser(description='QUick INTel - nmap and dns query wrapper.')
parser.add_argument("-s", action="store", dest="scant")
parser.add_argument("-t", action="store", dest="targ")
args = parser.parse_args()
target = args.targ
scantype = args.scant
print(args.scant)
print(args.targ)

def dnsQuery(rrtype, target):
    with urllib.request.urlopen("https://dns.google/resolve?name="+target+"&type="+rrtype) as url:
        data = json.loads(url.read().decode())
        print(json.dumps(data['Answer'], indent=4))
def nmapScan(params):
    os.system('nmap -v1' + ' ' + params + '-oX logs\\nmap_output.xml ' + target)
    isdir = os.path.isdir('logs')
    print(isdir)
    writeLogs()
def writeLogs():
    f = open("logs\\nmap_output.xml")
    xml_content = f.read()
    f.close()
    log = open("logs\\quint.json", "a")
    lastlog = open("logs\\lastlog.json", "w")
    newlog = [json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)]
    log.writelines(newlog)
    lastlog.writelines(newlog)
    log.close()
    lastlog.close()
def readOutputLog():
    with open('logs\\lastlog.json') as json_file:
        reporting = json.load(json_file)
    print(reporting['nmaprun']['host']['hostscript']['script']['@output'])
match scantype.upper():
    case "FULL":
        nmapscanoptions = '-T4 -sU -sS '
        nmapScan(nmapscanoptions)
    case "WHOIS":
        nmapscanoptions = '--script whois-domain.nse '
        nmapScan(nmapscanoptions)
        readOutputLog()
    case "WHOISIP":
        nmapscanoptions = '--script whois-ip --script-args whodb=nocache '
        nmapScan(nmapscanoptions)
        readOutputLog()
    case "MX":
        dnsQuery(scantype, target)
    case _:
        print("Nothing Selected")



