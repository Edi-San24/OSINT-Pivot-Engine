# Temp test file for validating connectors during build
# [DELETE BEFORE DEPLOYMENT!!!!]

from connectors.virustotal import VirusTotalConnector

vt = VirusTotalConnector()

# Test IP lookup
print("Testing IP lookup...")
result = vt.query_ip("8.8.8.8")
print(result)

# Test domain lookup
print("\nTesting domain lookup...")
result = vt.query_domain("google.com")
print(result)