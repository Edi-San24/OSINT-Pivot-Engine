import json

def display(label, result):
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"{'='*50}")
    print(json.dumps(result, indent=2))

from connectors.virustotal import VirusTotalConnector
from connectors.shodan import ShodanConnector
from connectors.whois import WHOISConnector
from connectors.passivedns import PassiveDNSConnector
from connectors.censys import CensysConnector

vt = VirusTotalConnector()
sd = ShodanConnector()
ws = WHOISConnector()
pdns = PassiveDNSConnector()
cs = CensysConnector()

display("VirusTotal - IP Lookup", vt.query_ip("8.8.8.8"))
display("VirusTotal - Domain Lookup", vt.query_domain("google.com"))
display("Shodan - IP Lookup", sd.query_ip("8.8.8.8"))
display("WHOIS - Domain Lookup", ws.query_domain("google.com"))
display("PassiveDNS - Domain Lookup", pdns.query_domain("google.com"))
display("PassiveDNS - IP Lookup", pdns.query_ip("8.8.8.8"))
display("Censys - IP Lookup", cs.query_ip("8.8.8.8"))