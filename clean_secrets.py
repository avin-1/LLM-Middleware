"""
Clean API tokens from documentation files
"""

import os
import re
from pathlib import Path

# Pattern to match the API token
TOKEN_PATTERN = r'hf_hgNp[A-Za-z0-9]*'
REPLACEMENT = 'hf_YOUR_TOKEN_HERE'

def clean_file(filepath):
    """Remove API tokens from a file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file contains the token
        if re.search(TOKEN_PATTERN, content):
            # Replace token
            new_content = re.sub(TOKEN_PATTERN, REPLACEMENT, content)
            
            # Write back
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"✅ Cleaned: {filepath}")
            return True
        return False
    except Exception as e:
        print(f"❌ Error cleaning {filepath}: {e}")
        return False

def main():
    """Clean all markdown files"""
    print("=" * 70)
    print("🧹 Cleaning API tokens from documentation files")
    print("=" * 70)
    print()
    
    cleaned_count = 0
    
    # Find all .md files
    for md_file in Path('.').rglob('*.md'):
        # Skip node_modules and .venv
        if 'node_modules' in str(md_file) or '.venv' in str(md_file):
            continue
        
        if clean_file(md_file):
            cleaned_count += 1
    
    print()
    print("=" * 70)
    print(f"✅ Cleaned {cleaned_count} files")
    print("=" * 70)
    print()
    print("Next steps:")
    print("1. git add .")
    print("2. git commit -m 'Remove API tokens from documentation'")
    print("3. git push origin main")
    print()

if __name__ == "__main__":
    main()
