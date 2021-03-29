#!/usr/bin/env python3
import json
import urllib.request
from re import match
import xmltodict
import os
from os import path
import argparse
from pathlib import Path
import platform

parser = argparse.ArgumentParser()
parser.add_argument('scant', nargs='?', type=str, help='help')
parser.add_argument('targ', nargs='?', type=str, help='help')
args = parser.parse_args()
scantype = args.scant
target = args.targ
print(scantype, target)

home = str(Path.home().joinpath('quint', 'logs'))
nmapxmlpath = str(Path(home).joinpath('nmap_output.xml'))
logfilepath = str(Path(home).joinpath('quint.json'))
lastlogpath = str(Path(home).joinpath('lastlog.json'))
def dnsQuery(rrtype, target):
    with urllib.request.urlopen("https://dns.google/resolve?name="+target+"&type="+rrtype) as url:
        data = json.loads(url.read().decode())
        print(json.dumps(data['Answer'], indent=4))
def nmapScan(params):
    match path.exists(home):
        case False:
            print("No Logs Directory, I'll create it...")
            Path(home).mkdir(parents = True, exist_ok = True)
            nmapScan(params)
        case _:
            print("starting scan...")
            match platform.system():
                case 'Linux':
                    os.system('sudo nmap -v0' + ' ' + params + '-oX ' + nmapxmlpath + ' ' + target)
                    writeLogs()
                case 'Windows':
                    os.system('nmap -v0' + ' ' + params + '-oX ' + nmapxmlpath + ' ' + target)
                    writeLogs()
def writeLogs():
    f = open(nmapxmlpath)
    xml_content = f.read()
    f.close()
    log = open(logfilepath, "a")
    lastlog = open(lastlogpath, "w")
    newlog = [json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)]
    log.writelines(newlog)
    lastlog.writelines(newlog)
    log.close()
    lastlog.close()
def readOutputLog():
    with open(lastlogpath) as json_file:
        clippedoutput = str(json.load(json_file)['nmaprun']['host']['hostscript']['script']['@output'])
        match clippedoutput.find('>>>') != -1:
            case True:
                main, extra = clippedoutput.split('>>>', 1)
                print(main)
            case False:
                print(clippedoutput)
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
    case "MX" | "A" | "SPF" | "ALL" | "CNAME":
        dnsQuery(scantype, target)
    case _:
        print("Nothing Selected")
