#!/usr/bin/env python3
import json
import urllib.request
from re import match
import xmltodict
import os
from os import path
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('scant', nargs='?', type=str, help='help')
parser.add_argument('targ', nargs='?', type=str, help='help')
args = parser.parse_args()
scantype = args.scant
target = args.targ
print(target, scantype)

home = str(Path.home()) + '/quint/logs'
def dnsQuery(rrtype, target):
    with urllib.request.urlopen("https://dns.google/resolve?name="+target+"&type="+rrtype) as url:
        data = json.loads(url.read().decode())
        print(json.dumps(data['Answer'], indent=4))
def nmapScan(params):
    match path.exists(home):
        case False:
            print("No Logs Directory, I'll create it...")
            os.makedirs(home)
            nmapScan(params)
        case _:
            print("starting scan...")
            os.system('sudo nmap -v0' + ' ' + params + '-oX ' + home + '/nmap_output.xml ' + target)
            writeLogs()
def writeLogs():
    f = open(home + "/nmap_output.xml")
    xml_content = f.read()
    f.close()
    log = open(home + "/quint.json", "a")
    lastlog = open(home + "/lastlog.json", "w")
    newlog = [json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)]
    log.writelines(newlog)
    lastlog.writelines(newlog)
    log.close()
    lastlog.close()
def readOutputLog():
    with open(home + '/lastlog.json') as json_file:
        outputjson = json.load(json_file)
        clippedoutput = outputjson['nmaprun']['host']['hostscript']['script']['@output']
        strclippedoutput = str(clippedoutput)
        match strclippedoutput.find('>>>') != -1:
            case True:
                main, extra = strclippedoutput.split('>>>', 1)
                print(main)
            case False:
                print(strclippedoutput)
            case _:
                print('Your output is messed up')

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
    case "MX" | "A" | "SPF" | "ALL":
        dnsQuery(scantype, target)
    case _:
        print("Nothing Selected")
