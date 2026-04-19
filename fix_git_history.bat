@echo off
echo ======================================================================
echo 🔧 Fixing Git History - Removing Secrets
echo ======================================================================
echo.

echo This will:
echo 1. Remove the secret from git history
echo 2. Force push to GitHub
echo.
echo ⚠️  WARNING: This rewrites git history!
echo.
pause

echo.
echo Step 1: Amending the commit with secrets...
git commit --amend --no-edit

echo.
echo Step 2: Force pushing to GitHub...
git push origin main --force

echo.
echo ======================================================================
echo ✅ Done!
echo ======================================================================
pause
