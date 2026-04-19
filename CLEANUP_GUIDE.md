# 🧹 Cleanup Guide - What to Keep vs Delete

## Summary

Your project has **many irrelevant directories and duplicate files**. Here's what to keep and what to delete.

---

## ✅ KEEP (Essential Files)

### Core Application
```
src/                          # Main SENTINEL Brain API (Python)
├── brain/                    # Core detection engines
│   ├── api/                  # FastAPI endpoints
│   ├── engines/              # Detection engines (injection, query, behavioral)
│   └── core/                 # Analyzer and core logic
└── sentinel/                 # CLI tools

sentinel-core/                # Rust engines (60+ detectors, not connected yet)
tests/                        # Test suite
docs/                         # Documentation
```

### Configuration
```
.env                          # Environment variables
.env.example                  # Example configuration
.gitignore                    # Git ignore rules
requirements.txt              # Python dependencies
pyproject.toml                # Project configuration
docker-compose.yml            # Docker setup
Dockerfile                    # Docker image
```

### Datasets & Testing
```
datasets/                     # Manual test datasets (100 samples)
datasets_real/                # Real internet datasets (570 samples)
test_real_datasets.py         # Test against real datasets
quick_benchmark.py            # Quick benchmark script
test_tricky_attacks.py        # Test advanced attacks
```

### Documentation (Keep These)
```
START_HERE.md                 # Main navigation guide
FINAL_STATUS.md               # Complete status report
BENCHMARK_RESULTS.md          # Benchmark analysis
FINAL_BENCHMARK_RESULTS.md    # Latest benchmark results
REAL_DATASET_IMPROVEMENTS.md  # Real dataset improvements
ARCHITECTURE_GAP_ANALYSIS.md  # Rust vs Python analysis
RUST_INTEGRATION_GUIDE.md     # How to integrate Rust
VALIDATION_DATASETS.md        # Dataset reference
TRICKY_TEST_CASES.md          # Attack explanations
POSTMAN_GUIDE.md              # API testing guide
HOW_DATASETS_WERE_MADE.md     # Dataset creation guide
```

### Utilities
```
restart_server.ps1            # Server restart script
restart_server.sh             # Server restart (Linux)
install.ps1                   # Installation script
install.sh                    # Installation (Linux)
SENTINEL_Brain_API.postman_collection.json  # Postman tests
```

### Reports
```
benchmark_report.json         # Benchmark results
real_datasets_report.json     # Real dataset results
validation_report.json        # Validation results
```

---

## ❌ DELETE (Irrelevant/Duplicate)

### Irrelevant Directories (Not Part of Core API)
```
devkit/                       # VS Code extension (separate project)
gomcp/                        # Go MCP server (not used)
immune/                       # Separate project
micro-swarm/                  # Separate project
papers/                       # Research papers (not needed)
patterns/                     # Not used
shield/                       # C implementation (not used)
strike/                       # Separate project
signatures/                   # Not used
migrations/                   # Database migrations (not used)
venv/                         # Duplicate of .venv
.pytest_cache/                # Test cache (regenerated)
.github/                      # GitHub workflows (not needed locally)
sentinel-sdk/                 # SDK (not used in core API)
scripts/                      # Old scripts (not used)
```

### Duplicate Documentation Files
```
POSTMAN_STEPS.md              # Duplicate of POSTMAN_GUIDE.md
POSTMAN_QUICK_START.txt       # Duplicate
README_POSTMAN.txt            # Duplicate
POSTMAN_TRICKY_TESTS.json     # Duplicate
QUICK_TRICKY_TESTS.txt        # Duplicate
VALIDATION_QUICK_START.md     # Duplicate of VALIDATION_DATASETS.md
DATASETS_SUMMARY.txt          # Duplicate
IMPROVEMENTS_SUMMARY.md       # Duplicate of IMPROVEMENTS_APPLIED.md
FINAL_RESULTS.md              # Duplicate of FINAL_BENCHMARK_RESULTS.md
QUICK_IMPROVEMENT_GUIDE.txt   # Duplicate
QUICK_IMPROVEMENT_SUMMARY.txt # Duplicate
RESTART_SERVER.md             # Duplicate
QUICKSTART.md                 # Duplicate of START_HERE.md
QUICK_START.md                # Duplicate
SHOW_STATUS.bat               # Not needed
START_SERVER.bat              # Use restart_server.ps1 instead
GAP_SUMMARY.txt               # Duplicate of ARCHITECTURE_GAP_ANALYSIS.md
QUICK_VALIDATION.txt          # Duplicate
VALIDATION_SUMMARY.md         # Duplicate
COMPLETE_VALIDATION_GUIDE.md  # Duplicate (keep VALIDATION_DATASETS.md)
IMPROVEMENTS_APPLIED.md       # Duplicate (keep REAL_DATASET_IMPROVEMENTS.md)
```

### Old/Unused Scripts
```
fix_and_start.py              # Old script
mock_test_llm.py              # Mock test (not needed)
quick_restart.py              # Use restart_server.ps1
test_all_endpoints.py         # Old test
test_api.py                   # Old test
test_deobfuscation.py         # Old test
test_detection.py             # Old test
fast_benchmark.py             # Duplicate of quick_benchmark.py
download_datasets.py          # Old (use download_real_datasets.py)
download_more_datasets.py     # Old
run_validation.py             # Old (use test_real_datasets.py)
```

---

## 🚀 How to Clean Up

### Option 1: Automatic Cleanup (Recommended)

Run the cleanup script:
```bash
cleanup_irrelevant.bat
```

This will:
- Delete all irrelevant directories
- Delete duplicate documentation
- Delete old scripts
- Keep all essential files

### Option 2: Manual Cleanup

Delete directories:
```bash
rmdir /s /q devkit gomcp immune micro-swarm papers patterns shield strike signatures migrations venv .pytest_cache .github sentinel-sdk scripts
```

Delete duplicate files:
```bash
del POSTMAN_STEPS.md POSTMAN_QUICK_START.txt README_POSTMAN.txt POSTMAN_TRICKY_TESTS.json QUICK_TRICKY_TESTS.txt VALIDATION_QUICK_START.md DATASETS_SUMMARY.txt IMPROVEMENTS_SUMMARY.md FINAL_RESULTS.md QUICK_IMPROVEMENT_GUIDE.txt QUICK_IMPROVEMENT_SUMMARY.txt RESTART_SERVER.md QUICKSTART.md QUICK_START.md SHOW_STATUS.bat START_SERVER.bat GAP_SUMMARY.txt QUICK_VALIDATION.txt VALIDATION_SUMMARY.md COMPLETE_VALIDATION_GUIDE.md IMPROVEMENTS_APPLIED.md
```

Delete old scripts:
```bash
del fix_and_start.py mock_test_llm.py quick_restart.py test_all_endpoints.py test_api.py test_deobfuscation.py test_detection.py fast_benchmark.py download_datasets.py download_more_datasets.py run_validation.py
```

---

## 📊 Before vs After

### Before Cleanup
```
Total Size: ~500MB+
Directories: 25+
Files: 100+
Confusion: High (too many files)
```

### After Cleanup
```
Total Size: ~50MB
Directories: 8 (essential only)
Files: ~40 (essential only)
Confusion: Low (clear structure)
```

---

## 📁 Final Clean Structure

```
AISecurity/
├── src/                      # Main API code
│   ├── brain/                # Detection engines
│   └── sentinel/             # CLI tools
├── sentinel-core/            # Rust engines (optional)
├── tests/                    # Test suite
├── docs/                     # Documentation
├── datasets/                 # Manual datasets
├── datasets_real/            # Real datasets
├── .venv/                    # Python virtual environment
├── .env                      # Configuration
├── requirements.txt          # Dependencies
├── docker-compose.yml        # Docker setup
├── test_real_datasets.py     # Main test script
├── quick_benchmark.py        # Quick benchmark
├── test_tricky_attacks.py    # Advanced tests
├── restart_server.ps1        # Server restart
├── START_HERE.md             # Main guide
├── FINAL_STATUS.md           # Status report
├── BENCHMARK_RESULTS.md      # Results
└── POSTMAN_GUIDE.md          # API testing

Total: Clean, organized, easy to navigate!
```

---

## ✅ Verification After Cleanup

After running cleanup, verify:

1. **Server still works:**
   ```bash
   python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000
   ```

2. **Tests still work:**
   ```bash
   python test_real_datasets.py
   python quick_benchmark.py
   python test_tricky_attacks.py
   ```

3. **Documentation accessible:**
   - Open `START_HERE.md`
   - Check `FINAL_STATUS.md`
   - Review `BENCHMARK_RESULTS.md`

---

## 🎯 Benefits of Cleanup

1. **Faster navigation** - Less clutter
2. **Clearer structure** - Know what's what
3. **Smaller size** - ~90% reduction
4. **Less confusion** - No duplicate files
5. **Easier maintenance** - Focus on essentials

---

## ⚠️ Important Notes

1. **Backup first** if you're unsure
2. **Don't delete** `.venv/` (Python virtual environment)
3. **Don't delete** `src/` (main code)
4. **Don't delete** `datasets/` and `datasets_real/` (test data)
5. **Keep** `sentinel-core/` if you plan to use Rust engines

---

## 🚀 Ready to Clean?

Run:
```bash
cleanup_irrelevant.bat
```

Or review this guide and delete manually.

**Your project will be much cleaner and easier to work with!** 🎉
