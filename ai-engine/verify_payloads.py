import json

# Verify payload database
with open('pentesting_payloads_7500.json', 'r') as f:
    db = json.load(f)

print('\n✅ CYBERSPLOI Payload Database Verification\n')
print(f"Total Payloads: {db['metadata']['total_payloads']:,}")
print(f"Version: {db['metadata']['version']}")
print(f"Date: {db['metadata']['expansion_date']}")
print(f"\n📊 Category Breakdown:\n")

cats = [k for k in db.keys() if k != 'metadata']
total = 0
critical_count = 0
high_count = 0

for cat in sorted(cats):
    data = db[cat]
    count = data.get('total', 0)
    severity = data.get('severity', 'N/A')
    cvss = data.get('cvss_base', 0)
    total += count
    
    if severity.lower() == 'critical':
        critical_count += count
    elif severity.lower() == 'high':
        high_count += count
    
    is_new = " ⭐ NEW" if "NEW" in data.get('description', '') else ""
    print(f"  • {cat:35s} {count:4d} {severity:8s} (CVSS {cvss:5.1f}){is_new}")

print(f"\n{'='*75}")
print(f"Total: {total:,} payloads across {len(cats)} categories")
print(f"Critical: {critical_count:,} | High: {high_count:,}")
print(f"\n✅ Database Ready for CYBERSPLOI AI Pentester Engine")
