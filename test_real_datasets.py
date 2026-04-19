#!/usr/bin/env python3
"""
Test against REAL datasets downloaded from internet
"""
import requests
import json
import time
from pathlib import Path

BASE_URL = "http://localhost:8000/api/v1/analyze"
DATASETS_DIR = Path("datasets_real")

def test_dataset(name, filename, expected_malicious, max_samples=50):
    """Test a dataset"""
    print(f"\n{'='*70}")
    print(f"Testing: {name}")
    print(f"{'='*70}")
    
    filepath = DATASETS_DIR / filename
    if not filepath.exists():
        print(f"❌ Dataset not found: {filename}")
        return None
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        samples = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Limit samples for faster testing
    if len(samples) > max_samples:
        samples = samples[:max_samples]
        print(f"Testing first {max_samples} of {len(samples)} samples")
    else:
        print(f"Testing all {len(samples)} samples")
    
    detected = 0
    latencies = []
    
    for i, sample in enumerate(samples, 1):
        try:
            start = time.time()
            response = requests.post(
                BASE_URL,
                json={"text": sample, "profile": "standard"},
                timeout=10
            )
            latency = (time.time() - start) * 1000
            latencies.append(latency)
            
            if response.status_code == 200:
                result = response.json()
                verdict = result.get("verdict", "UNKNOWN")
                is_detected = verdict in ["BLOCK", "WARN"]
                
                if expected_malicious and is_detected:
                    detected += 1
                elif not expected_malicious and not is_detected:
                    detected += 1
        except Exception as e:
            pass
        
        # Progress
        if i % 10 == 0 or i == len(samples):
            accuracy = (detected / i) * 100
            print(f"  Progress: {i}/{len(samples)} ({accuracy:.1f}% accurate)", end='\r')
    
    print()  # New line
    
    accuracy = (detected / len(samples)) * 100
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    print(f"\n✅ Results:")
    print(f"   Detected: {detected}/{len(samples)} ({accuracy:.1f}%)")
    print(f"   Avg Latency: {avg_latency:.0f}ms")
    
    return {
        "name": name,
        "file": filename,
        "total": len(samples),
        "detected": detected,
        "accuracy": accuracy,
        "latency": avg_latency
    }

def main():
    print("="*70)
    print("🎯 SENTINEL - Testing Against REAL Internet Datasets")
    print("="*70)
    
    # Check server
    try:
        requests.get("http://localhost:8000/v1/health", timeout=2)
    except:
        print("\n❌ Server not running!")
        print("Start with: python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000")
        return
    
    results = []
    
    # Test SQL Injection
    print("\n🔴 SQL INJECTION ATTACKS")
    r = test_dataset("SQL Injection (fuzzdb)", "sql_fuzzdb.txt", True, max_samples=50)
    if r: results.append(r)
    
    # Test XSS
    print("\n🔴 XSS ATTACKS")
    r = test_dataset("XSS (fuzzdb)", "xss_fuzzdb.txt", True, max_samples=50)
    if r: results.append(r)
    
    # Test Command Injection
    print("\n🔴 COMMAND INJECTION ATTACKS")
    r = test_dataset("Command Injection (fuzzdb)", "command_fuzzdb.txt", True, max_samples=50)
    if r: results.append(r)
    r = test_dataset("Command Injection (PayloadsAllTheThings)", "command_injection_real.txt", True, max_samples=50)
    if r: results.append(r)
    
    # Test Prompt Injection
    print("\n🔴 PROMPT INJECTION / JAILBREAK ATTACKS")
    r = test_dataset("Prompt Injection", "prompt_injection_real.txt", True, max_samples=50)
    if r: results.append(r)
    r = test_dataset("Jailbreak Prompts", "jailbreak_prompts.txt", True, max_samples=50)
    if r: results.append(r)
    
    # Summary
    print(f"\n{'='*70}")
    print("📊 FINAL RESULTS - REAL INTERNET DATASETS")
    print(f"{'='*70}\n")
    
    total_samples = sum(r["total"] for r in results)
    total_detected = sum(r["detected"] for r in results)
    overall_accuracy = (total_detected / total_samples * 100) if total_samples > 0 else 0
    avg_latency = sum(r["latency"] for r in results) / len(results) if results else 0
    
    print(f"Overall Performance:")
    print(f"  Total Samples Tested: {total_samples}")
    print(f"  Correctly Detected: {total_detected}")
    print(f"  Overall Accuracy: {overall_accuracy:.1f}%")
    print(f"  Average Latency: {avg_latency:.0f}ms")
    print()
    
    print("Breakdown by Dataset:")
    print(f"{'Dataset':<45} {'Samples':<10} {'Accuracy':<12}")
    print("-" * 70)
    for r in results:
        print(f"{r['name']:<45} {r['total']:<10} {r['accuracy']:.1f}%")
    print()
    
    # Rating
    if overall_accuracy >= 95:
        rating = "🏆 EXCELLENT"
    elif overall_accuracy >= 90:
        rating = "🥇 VERY GOOD"
    elif overall_accuracy >= 80:
        rating = "🥈 GOOD"
    elif overall_accuracy >= 70:
        rating = "🥉 FAIR"
    else:
        rating = "⚠️  NEEDS IMPROVEMENT"
    
    print(f"Overall Rating: {rating}")
    print()
    
    # Save report
    report = {
        "source": "Real Internet Datasets",
        "total_samples": total_samples,
        "total_detected": total_detected,
        "overall_accuracy": overall_accuracy,
        "avg_latency": avg_latency,
        "datasets": results
    }
    
    with open("real_datasets_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Report saved to: real_datasets_report.json")
    print(f"{'='*70}")
    
    # Comparison
    print("\n📊 COMPARISON: Manual vs Real Datasets")
    print(f"{'='*70}")
    print(f"{'Source':<30} {'Samples':<15} {'Accuracy':<15}")
    print("-" * 70)
    print(f"{'Manual Datasets':<30} {'100':<15} {'85%':<15}")
    print(f"{'Real Internet Datasets':<30} {f'{total_samples}':<15} {f'{overall_accuracy:.1f}%':<15}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
