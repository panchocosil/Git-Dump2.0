# Git Dump 2.0 (Enhanced Multi-Target Version)

This tool attempts to recover a `.git` directory exposed over HTTP/HTTPS and reconstruct the repository locally.  
It supports **single-target** mode or **multi-target list processing** from a file.

## Features
- Supports dumping a **single repository** or **multiple repositories** from a list (`-f urls.txt`).
- Automatically names output directories when only a URL is given.
- Parallel processing:
  - `--parallel-targets` → process multiple URLs at the same time.
  - `-j` → parallelize file fetching inside each target.
- Supports **client certificates** in PKCS#12 format.
- Proxy support (SOCKS4, SOCKS5, HTTP).
- Sanitizes `.git/config` to disable potentially dangerous hooks before checkout.
- Fully restores the working tree with `git checkout .`.

---

## How It Works

1. **Check for Directory Listing**  
   - If `/.git/` is browsable, recursively downloads the `.git` directory and runs `git checkout .`.

2. **If Listing Is Disabled**  
   - **Fetch common files**: `.gitignore`, `.git/HEAD`, `.git/index`, `.git/config`, hooks, etc.  
   - **Find refs**: Parses `.git/HEAD`, `.git/packed-refs`, `.git/logs/*` to find branch/tag references.  
   - **Find objects**: Looks for 40-char SHA1 hashes in refs, logs, and `index`; checks packfiles.  
   - **Fetch objects recursively**: For each commit/tree/blob, fetches referenced objects.  
   - **Rebuild working tree**: Runs `git checkout .` to restore repository contents.

---

## Installation
```bash
git clone https://github.com/panchocosil/git-dump2.0.git
cd git-dump2.0
pip3 install -r requirements.txt
```

Requirements (Python 3):
	•	requests
	•	bs4
	•	dulwich
	•	urllib3
	•	requests-pkcs12
	•	pysocks

⸻

Usage

Single Target
```
python3 git-dump.py https://target.tld ./output-dir
```

Multiple Targets from a File

urls.txt can contain:
```
https://target1.tld/.git/
https://target2.tld/.git/ custom/output/path
```

	•	If only a URL is given, the tool will auto-generate the output directory name.
	•	If DIR is also given, it will be used as the output path.

Run:
```
python3 git-dump.py -f urls.txt --out-base dumps --parallel-targets 4
```

⸻

Options
```
Option	Description
-f, --file	File containing list of targets (one per line, optionally URL DIR).
--out-base	Base directory for auto-generated output folders (default: .).
--parallel-targets	Number of targets from the list to process in parallel.
-j, --jobs	Parallel requests inside a single target (default: 10).
-r, --retry	Retry count for failed requests (default: 3).
-t, --timeout	Timeout per request in seconds (default: 3).
-u, --user-agent	User-Agent string.
-H, --header	Add extra HTTP headers (NAME=VALUE).
--proxy	Use proxy (socks5:host:port, http://host:port, etc.).
--client-cert-p12	Client certificate in PKCS#12 format.
--client-cert-p12-password	Password for the PKCS#12 file.
```

⸻

Example

urls.txt
```
http://example.com:8008/.git/
http://example.com/user/.git/
https://example.com/.git/
https://example.com/.git/
```

Run:
```
python3 git-dump.py -f urls.txt --out-base dumps --parallel-targets 4 -j 10 -t 5
```

This will:
	•	Create dumps/pixbradesco.koandina.com_8008_.git and similar folders.
	•	Attempt to recover each exposed .git repo.
	•	Restore files with git checkout . inside each recovered repo.

⸻

Disclaimer

This tool is for educational and authorized security testing only.
Accessing .git repositories without permission is illegal in many jurisdictions.
