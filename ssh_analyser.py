from collections import defaultdict
import re

LOG_FILE = "auth.log"
THRESHOLD = 10

failed = defaultdict(int)
ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')

with open(LOG_FILE) as f:
    for line in f:
        if "Failed password" in line:
            parts = line.split()
            try:
                ip = parts[10]
                if ip_pattern.match(ip):
                    failed[ip] += 1
            except IndexError:
                continue

print("\n=== SSH Brute Force Detection ===\n")
print(f"{'IP Address':<20} {'Attempts':>10} {'Status'}")
print("-" * 45)
for ip, count in sorted(failed.items(), key=lambda x: -x[1]):
    status = "ALERT - BRUTE FORCE" if count >= THRESHOLD else "OK"
    print(f"{ip:<20} {count:>10}     {status}")

print(f"\nTotal IPs analysed: {len(failed)}")
print(f"Attackers detected: {sum(1 for c in failed.values() if c >= THRESHOLD)}")