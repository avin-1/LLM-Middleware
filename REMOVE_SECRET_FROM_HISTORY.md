# 🔧 Remove Secret from Git History

## The Problem

The secret is in an old commit (`a6d7419`) in your git history, even though we cleaned the current files.

## Solution: Rewrite Git History

### Option 1: Simple Amend (If it's the last commit)

```bash
# Make sure all files are cleaned
python clean_secrets.py

# Stage the changes
git add .

# Amend the last commit
git commit --amend --no-edit

# Force push
git push origin main --force
```

### Option 2: Use BFG Repo-Cleaner (Recommended for older commits)

```bash
# Download BFG
# https://rtyley.github.io/bfg-repo-cleaner/

# Replace the secret in all history
java -jar bfg.jar --replace-text passwords.txt

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push
git push origin main --force
```

### Option 3: Filter-branch (Manual)

```bash
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch MODEL_SELECTION_GUIDE.md" \
  --prune-empty --tag-name-filter cat -- --all

git push origin main --force
```

---

## Easiest Solution: Allow the Secret on GitHub

Since this is your personal token and the repo might be private:

1. Click the GitHub link in the error message
2. Allow the secret to be pushed
3. Then push normally

**OR**

Revoke the old token and create a new one:
1. Go to: https://huggingface.co/settings/tokens
2. Revoke: `hf_YOUR_TOKEN_HERE...`
3. Create new token
4. Update `.env` with new token
5. Push will work (old token is invalid)

---

## Quick Fix (Recommended)

### Step 1: Revoke Old Token

Go to: https://huggingface.co/settings/tokens

Revoke the token that starts with `hf_YOUR_TOKEN_HERE...`

### Step 2: Create New Token

Create a new token on Hugging Face

### Step 3: Update .env

```bash
# In .env
HF_TOKEN=hf_YOUR_NEW_TOKEN_HERE
HUGGINGFACE_API_KEY=hf_YOUR_NEW_TOKEN_HERE
```

### Step 4: Push

```bash
git push origin main
```

GitHub will allow the push because the old token is now invalid!

---

## Alternative: Force Push

If you don't care about git history:

```bash
# Clean files
python clean_secrets.py

# Add all changes
git add .

# Amend last commit
git commit --amend -m "Remove secrets and add LLM integration"

# Force push
git push origin main --force
```

---

**Recommended: Revoke the old token, create a new one, then push!** 🔐
