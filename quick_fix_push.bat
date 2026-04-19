@echo off
echo ======================================================================
echo 🔧 Quick Fix - Amend and Force Push
echo ======================================================================
echo.

echo This will:
echo 1. Clean any remaining secrets
echo 2. Amend the last commit
echo 3. Force push to GitHub
echo.
echo ⚠️  This rewrites git history!
echo.
set /p CONTINUE="Continue? (y/n): "
if /i not "%CONTINUE%"=="y" exit /b

echo.
echo Step 1: Cleaning secrets...
python clean_secrets.py

echo.
echo Step 2: Staging changes...
git add .

echo.
echo Step 3: Amending commit...
git commit --amend --no-edit

echo.
echo Step 4: Force pushing...
git push origin main --force

echo.
echo ======================================================================
if errorlevel 1 (
    echo ❌ Push failed!
    echo.
    echo Try this instead:
    echo 1. Go to: https://huggingface.co/settings/tokens
    echo 2. Revoke the old token
    echo 3. Create a new token
    echo 4. Update .env with new token
    echo 5. Run: git push origin main
) else (
    echo ✅ Success! Pushed to GitHub
)
echo ======================================================================
pause
