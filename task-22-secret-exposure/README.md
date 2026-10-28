# Task 22: The Secret Accidentally Published

## Goal
A developer publishes a config file with what looks like an API credential in a public repository and deletes it five minutes later. Assess the situation, and propose immediate response, verification and prevention steps.

All credentials in this task are synthetic (fake).

## Files
- scan_secrets.py: small defensive scanner that finds secret-like text in files and hides the value in its report
- sample_repo/: synthetic project. config.env contains fake secrets; app.py (reads secrets from environment variables) and notes.txt are clean

## How to run
cd task-22-secret-exposure
python scan_secrets.py

## Assessment: what do we know?
| Known | Unknown |
|---|---|
| A credential-like value was public in a repo | Is the credential real and still valid? |
| The file was deleted after 5 minutes | What permissions does it have? |
| | Did anyone copy it, or a bot scan it, in those 5 minutes? |
| | Is it still in git history, forks or caches? |

Conclusion: deleting the file does NOT make the secret safe. Public repositories can be scanned or copied within minutes, and git keeps the old version in history. Assume the secret is compromised.

## Prioritized response plan
| Priority | Action | Why |
|---|---|---|
| 1 | Treat the credential as compromised | Deletion does not undo exposure |
| 2 | Revoke and rotate it (issue a new one, update the apps, disable the old one) | The only step that actually removes the attacker's access |
| 3 | Check the provider's logs for use between publishing and revoking (unknown IPs, new resources, unusual billing) | Tells us if it was misused |
| 4 | Find the scope: what could it access, and did the file hold other secrets? | Decides how big the incident is |
| 5 | Remove it from git history (git filter-repo or BFG) and force push | Secondary, because forks and caches may still hold a copy |
| 6 | Tell the security owner or team lead and record a timeline | Needed for follow-up and any required notifications |
| 7 | Add prevention (below) | Stops it from happening again |

## Demo: deleting a file does not remove it from history
In a temporary folder I committed a fake config.env, deleted it, and committed again. `git log -p` still showed the fake key in the older commit. This proves that rotating the credential matters more than deleting the file.

## Prevention
- Keep secrets in environment variables or a secrets manager, not in code (see sample_repo/app.py)
- Add secret files such as .env to .gitignore
- Use a pre-commit secret scanner (for example gitleaks) and GitHub secret scanning with push protection
- Give keys least privilege and short lifetimes
- Review code before merging, and train developers on this incident type
- Root cause to ask: why was a real credential in a config file, and why was there no check before pushing?

## Tool results
Running scan_secrets.py on sample_repo flags config.env lines 4 and 5 (API key and password), and reports nothing for app.py and notes.txt. The report hides the secret values.

## What I learned
- The first priority is revoking the credential, not deleting the file
- Git history keeps old content
- Prevention is cheaper than cleanup

## MITRE ATT&CK
T1552.001 (Unsecured Credentials: Credentials In Files), T1078 (Valid Accounts, if the leaked credential is used)

## Limitations
- The scanner uses simple patterns, so it can give false positives and miss unusual secret formats
- It scans current files only, not git history
- Real tools do much more (entropy checks, history scans, provider verification)
- Facts about the real exposure (permissions, misuse) cannot be known from this simulation