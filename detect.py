import csv
from datetime import datetime, timedelta

# Ground truth: the IPs we KNOW are attackers (we made the data)
MALICIOUS = {"203.0.113.9", "198.51.100.7", "192.0.2.50"}

def load_logs(path):
    events = []
    with open(path) as f:
        for row in csv.DictReader(f):
            row["time"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            events.append(row)
    return events

def group_by_ip(events):
    groups = {}
    for e in events:
        groups.setdefault(e["ip"], []).append(e)
    return groups

def rule_v1(events):
    """Alert if an IP has 3+ failed logins (any time)."""
    alerts = set()
    for ip, evs in group_by_ip(events).items():
        fails = [e for e in evs if e["status"] == "FAIL"]
        if len(fails) >= 3:
            alerts.add(ip)
    return alerts

def rule_v2(events):
    """Alert if 3+ fails within 5 min, OR success right after 2+ fails within 5 min."""
    alerts = set()
    window = timedelta(minutes=5)
    for ip, evs in group_by_ip(events).items():
        evs.sort(key=lambda e: e["time"])
        for i, e in enumerate(evs):
            recent_fails = [x for x in evs[:i + 1]
                            if x["status"] == "FAIL" and e["time"] - x["time"] <= window]
            if e["status"] == "FAIL" and len(recent_fails) >= 3:
                alerts.add(ip)
            if e["status"] == "SUCCESS" and len(recent_fails) >= 2:
                alerts.add(ip)
    return alerts

def score(name, alerts):
    print(f"\n=== {name} ===")
    print("Caught (true positives):   ", sorted(alerts & MALICIOUS))
    print("Wrongly flagged (false +): ", sorted(alerts - MALICIOUS))
    print("Missed (false negatives):  ", sorted(MALICIOUS - alerts))

if __name__ == "__main__":
    events = load_logs("logs.csv")
    score("Rule v1 (3+ fails, any time)", rule_v1(events))
    score("Rule v2 (3+ fails in 5 min OR fails then success)", rule_v2(events))