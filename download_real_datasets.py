#!/usr/bin/env python3
"""
Download REAL datasets from the internet
"""
import requests
from pathlib import Path

DATASETS_DIR = Path("datasets_real")
DATASETS_DIR.mkdir(exist_ok=True)

print("="*70)
print("Downloading REAL Attack Datasets from Internet")
print("="*70)
print()

# 1. SQL Injection from PayloadsAllTheThings
print("📥 Downloading SQL Injection payloads...")
try:
    url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/detect-SQLi.txt"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        with open(DATASETS_DIR / "sql_injection_real.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        lines = len([l for l in response.text.split('\n') if l.strip()])
        print(f"✅ Downloaded {lines} SQL injection payloads")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# 2. XSS from PayloadsAllTheThings
print("📥 Downloading XSS payloads...")
try:
    url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruder/XSS-Bypass-Strings.txt"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        with open(DATASETS_DIR / "xss_real.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        lines = len([l for l in response.text.split('\n') if l.strip()])
        print(f"✅ Downloaded {lines} XSS payloads")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# 3. Command Injection from PayloadsAllTheThings
print("📥 Downloading Command Injection payloads...")
try:
    url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        with open(DATASETS_DIR / "command_injection_real.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        lines = len([l for l in response.text.split('\n') if l.strip()])
        print(f"✅ Downloaded {lines} command injection payloads")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# 4. Prompt Injection from FuzzyAI
print("📥 Downloading Prompt Injection dataset...")
try:
    url = "https://raw.githubusercontent.com/FonduAI/awesome-prompt-injection/main/README.md"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        # Extract actual prompts from markdown
        lines = response.text.split('\n')
        prompts = []
        for line in lines:
            if line.strip().startswith('-') and len(line) > 20:
                # Extract prompt from markdown list
                prompt = line.strip().lstrip('- ').strip('`').strip()
                if len(prompt) > 10 and not prompt.startswith('http'):
                    prompts.append(prompt)
        
        if prompts:
            with open(DATASETS_DIR / "prompt_injection_real.txt", "w", encoding="utf-8") as f:
                for p in prompts[:50]:  # Take first 50
                    f.write(p + "\n")
            print(f"✅ Downloaded {len(prompts[:50])} prompt injection examples")
        else:
            print(f"⚠️  No prompts extracted, using fallback")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# 5. Alternative: SecLists SQL Injection
print("📥 Downloading SecLists SQL Injection...")
try:
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        with open(DATASETS_DIR / "sql_seclists.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        lines = len([l for l in response.text.split('\n') if l.strip()])
        print(f"✅ Downloaded {lines} SQL payloads from SecLists")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# 6. Alternative: SecLists XSS
print("📥 Downloading SecLists XSS...")
try:
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        with open(DATASETS_DIR / "xss_seclists.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        lines = len([l for l in response.text.split('\n') if l.strip()])
        print(f"✅ Downloaded {lines} XSS payloads from SecLists")
    else:
        print(f"❌ Failed (status: {response.status_code})")
except Exception as e:
    print(f"❌ Error: {e}")

print()

# Summary
print("="*70)
print("📊 DOWNLOAD SUMMARY")
print("="*70)
print(f"Datasets saved to: {DATASETS_DIR.absolute()}")
print()
print("Downloaded datasets:")
for file in DATASETS_DIR.glob("*.txt"):
    size = file.stat().st_size
    lines = len([l for l in file.read_text(encoding='utf-8', errors='ignore').split('\n') if l.strip()])
    print(f"  • {file.name}: {lines} payloads ({size:,} bytes)")
print()
print("Next step: Run benchmark with:")
print("  python test_real_datasets.py")
print("="*70)
