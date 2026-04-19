#!/usr/bin/env python3
"""
Quick benchmark against downloaded datasets
"""
import requests
import json
import time
from pathlib import Path

BASE_URL = "http://localhost:8000/api/v1/analyze"
DATASETS_DIR = Path("datasets")

def test_dataset(name, filename, expected_malicious):
    """Test a dataset and return results"""
    print(f"\n{'='*70}")
    print(f"Testing: {name}")
    print(f"{'='*70}")
    
    filepath = DATASETS_DIR / filename
    if not filepath.exists():
        print(f"❌ Dataset not found: {filename}")
        return None
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        samples = [line.strip() for line in f if line.strip()]
    
    print(f"Samples: {len(samples)}")
    print(f"Expected: {'Malicious' if expected_malicious else 'Safe'}")
    
    detected = 0
    missed = 0
    latencies = []
    
    for i, sample in enumerate(samples, 1):
        try:
            start = time.time()
            response = requests.post(
                BASE_URL,
                json={"text": sample, "profile": "standard"},
                timeout=5
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
                else:
                    missed += 1
                    if i <= 5:  # Show first 5 misses
                        print(f"  Miss: {sample[:60]}... -> {verdict}")
            else:
                missed += 1
                
        except Exception as e:
            missed += 1
            if i <= 3:
                print(f"  Error: {str(e)[:60]}")
        
        # Progress
        if i % 5 == 0 or i == len(samples):
            accuracy = (detected / i) * 100
            print(f"  Progress: {i}/{len(samples)} ({accuracy:.1f}% accurate)", end='\r')
    
    print()  # New line
    
    total = len(samples)
    accuracy = (detected / total) * 100 if total > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    print(f"\n✅ Results:")
    print(f"   Detected: {detected}/{total} ({accuracy:.1f}%)")
    print(f"   Missed: {missed}")
    print(f"   Avg Latency: {avg_latency:.1f}ms")
    
    return {
        "name": name,
        "total": total,
        "detected": detected,
        "missed": missed,
        "accuracy": accuracy,
        "avg_latency": avg_latency
    }

def main():
    print("="*70)
    print("🎯 SENTINEL Brain API - Quick Benchmark")
    print("="*70)
    
    # Check server
    try:
        response = requests.get("http://localhost:8000/v1/health", timeout=2)
        if response.status_code != 200:
            print("\n❌ Server not responding. Start with: .\\restart_server.ps1")
            return
    except:
        print("\n❌ Server not running. Start with: .\\restart_server.ps1")
        return
    
    results = []
    
    # Test malicious datasets
    print("\n🔴 Testing Malicious Datasets...")
    results.append(test_dataset("Prompt Injection", "prompt_injection.txt", True))
    results.append(test_dataset("SQL Injection", "sql_injection.txt", True))
    results.append(test_dataset("XSS Payloads", "xss_payloads.txt", True))
    results.append(test_dataset("Command Injection", "command_injection.txt", True))
    
    # Test safe dataset
    print("\n🟢 Testing Safe Dataset...")
    results.append(test_dataset("Safe Prompts", "safe_prompts.txt", False))
    
    # Summary
    print(f"\n{'='*70}")
    print("📊 BENCHMARK SUMMARY")
    print(f"{'='*70}\n")
    
    total_samples = sum(r["total"] for r in results if r)
    total_detected = sum(r["detected"] for r in results if r)
    overall_accuracy = (total_detected / total_samples * 100) if total_samples > 0 else 0
    avg_latency = sum(r["avg_latency"] for r in results if r) / len([r for r in results if r])
    
    print(f"Overall Performance:")
    print(f"  Total Tests: {total_samples}")
    print(f"  Correct: {total_detected}")
    print(f"  Accuracy: {overall_accuracy:.1f}%")
    print(f"  Avg Latency: {avg_latency:.1f}ms")
    print()
    
    print("Dataset Breakdown:")
    print(f"{'Dataset':<25} {'Samples':<10} {'Accuracy':<12} {'Latency':<10}")
    print("-" * 70)
    for r in results:
        if r:
            print(f"{r['name']:<25} {r['total']:<10} {r['accuracy']:.1f}%{'':<7} {r['avg_latency']:.1f}ms")
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
        "overall_accuracy": overall_accuracy,
        "total_samples": total_samples,
        "total_detected": total_detected,
        "avg_latency": avg_latency,
        "datasets": results
    }
    
    with open("benchmark_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Report saved to: benchmark_report.json")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
