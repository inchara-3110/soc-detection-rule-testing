# Task 9: Testing a Brute-Force Detection Rule

## Goal
Test a login-attack detection rule on synthetic logs, find where it fails, and improve it.

## Files
- logs.csv: synthetic login logs (normal users + attackers)
- detect.py: Rule v1, Rule v2, and the scoring code

## How to run
python detect.py

## Results
| Rule | Caught | False positives | Missed |
|---|---|---|---|
| v1: 3+ fails, any time | 2 attackers | bob (slow typos) | 192.0.2.50 |
| v2: 3+ fails in 5 min, or fails then success | 3 attackers | none | none |

## What I learned
- v1 ignores time, so slow innocent mistakes look like attacks.
- v2 adds a time window and the "fails then success" pattern.

## MITRE ATT&CK
T1110 (Brute Force)

## Limitations
- Small synthetic dataset.
- Attackers can slow down to dodge the 5-minute window.