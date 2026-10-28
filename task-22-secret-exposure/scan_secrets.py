import os
import re
import sys

# Patterns that look like secrets. Defensive tool: it only READS files and
# never prints the full secret.
PATTERNS = {
    "AWS-style access key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub-style token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Hard-coded credential": re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*[\"']?([A-Za-z0-9_\-/+]{12,})"
    ),
}

SKIP_DIRS = {".git", "__pycache__", "node_modules"}


def preview_of(name, match):
    """Hide the secret value so the report itself does not leak it."""
    if name == "Hard-coded credential":
        return match.group(1) + " = ********"
    return match.group(0)[:4] + "********"


def scan_folder(folder):
    findings = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for filename in sorted(files):
            path = os.path.join(root, filename)
            with open(path, "r", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    for name, pattern in PATTERNS.items():
                        match = pattern.search(line)
                        if match:
                            findings.append({
                                "file": path,
                                "line": line_no,
                                "type": name,
                                "preview": preview_of(name, match),
                            })
    return findings


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "sample_repo"
    print(f"Scanning folder: {folder}\n")
    results = scan_folder(folder)

    for r in results:
        print(f"[HIGH] {r['file']} (line {r['line']})")
        print(f"       Type   : {r['type']}")
        print(f"       Found  : {r['preview']}\n")

    if results:
        print(f"Scan complete: {len(results)} possible secret(s) found.")
        sys.exit(1)
    else:
        print("Scan complete: no secrets found.")