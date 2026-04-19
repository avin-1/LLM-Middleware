@echo off
echo ========================================
echo Cleaning up irrelevant files/directories
echo ========================================
echo.

echo Deleting irrelevant directories...
if exist devkit rmdir /s /q devkit
if exist gomcp rmdir /s /q gomcp
if exist immune rmdir /s /q immune
if exist micro-swarm rmdir /s /q micro-swarm
if exist papers rmdir /s /q papers
if exist patterns rmdir /s /q patterns
if exist shield rmdir /s /q shield
if exist strike rmdir /s /q strike
if exist signatures rmdir /s /q signatures
if exist migrations rmdir /s /q migrations
if exist venv rmdir /s /q venv
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist .github rmdir /s /q .github

echo.
echo Deleting duplicate documentation files...
del /q POSTMAN_STEPS.md 2>nul
del /q POSTMAN_QUICK_START.txt 2>nul
del /q README_POSTMAN.txt 2>nul
del /q POSTMAN_TRICKY_TESTS.json 2>nul
del /q QUICK_TRICKY_TESTS.txt 2>nul
del /q VALIDATION_QUICK_START.md 2>nul
del /q DATASETS_SUMMARY.txt 2>nul
del /q IMPROVEMENTS_SUMMARY.md 2>nul
del /q FINAL_RESULTS.md 2>nul
del /q QUICK_IMPROVEMENT_GUIDE.txt 2>nul
del /q RESTART_SERVER.md 2>nul
del /q QUICKSTART.md 2>nul
del /q QUICK_START.md 2>nul
del /q SHOW_STATUS.bat 2>nul
del /q START_SERVER.bat 2>nul

echo.
echo Deleting old test scripts...
del /q fix_and_start.py 2>nul
del /q mock_test_llm.py 2>nul
del /q quick_restart.py 2>nul
del /q test_all_endpoints.py 2>nul
del /q test_api.py 2>nul
del /q test_deobfuscation.py 2>nul
del /q test_detection.py 2>nul
del /q fast_benchmark.py 2>nul

echo.
echo Deleting old dataset downloaders...
del /q download_datasets.py 2>nul
del /q download_more_datasets.py 2>nul

echo.
echo Deleting old validation scripts...
del /q run_validation.py 2>nul

echo.
echo ========================================
echo Cleanup complete!
echo ========================================
echo.
echo Kept important files:
echo   - src/ (main API code)
echo   - sentinel-core/ (Rust engines)
echo   - tests/ (test suite)
echo   - datasets/ and datasets_real/ (test data)
echo   - docs/ (documentation)
echo   - Key scripts: test_real_datasets.py, quick_benchmark.py, test_tricky_attacks.py
echo   - Key docs: START_HERE.md, FINAL_STATUS.md, BENCHMARK_RESULTS.md
echo.
pause
