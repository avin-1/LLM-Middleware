"""
Quick test script to verify Hugging Face API key and model access.
"""

import os
import asyncio
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_huggingface_api():
    """Test Hugging Face API connection."""
    
    # Get configuration
    api_key = os.environ.get("HUGGINGFACE_API_KEY") or os.environ.get("HR_TOKEN")
    model = os.environ.get("LLM_MODEL", "gpt2")
    
    print("=" * 70)
    print("🧪 Testing Hugging Face API")
    print("=" * 70)
    print(f"API Key: {api_key[:10]}..." if api_key else "❌ No API key found")
    print(f"Model: {model}")
    
    # Warn about large models
    if "120b" in model.lower() or "gpt-oss" in model.lower():
        print()
        print("⚠️  WARNING: This is a LARGE model (120B parameters)")
        print("   First request may take 60-120 seconds to load!")
        print("   Please be patient...")
    
    print()
    
    if not api_key:
        print("❌ ERROR: No API key found!")
        print("Add HUGGINGFACE_API_KEY or HR_TOKEN to .env file")
        return
    
    # Test API
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "inputs": "Hello, how are you?",
        "parameters": {
            "max_new_tokens": 50,
            "temperature": 0.7,
            "return_full_text": False,
        },
        "options": {
            "wait_for_model": True,
        }
    }
    
    print("📡 Sending test request...")
    print(f"URL: {url}")
    print()
    print("⏳ Waiting for response (may take 60-120 seconds for large models)...")
    print()
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:  # Increased timeout for large models
            response = await client.post(url, headers=headers, json=payload)
            
            print(f"Status Code: {response.status_code}")
            print()
            
            if response.status_code == 200:
                result = response.json()
                print("✅ SUCCESS! API is working!")
                print()
                print("Response:")
                print("-" * 70)
                
                if isinstance(result, list) and len(result) > 0:
                    generated = result[0].get("generated_text", "")
                    print(f"Input: Hello, how are you?")
                    print(f"Output: {generated}")
                elif isinstance(result, dict):
                    generated = result.get("generated_text", "")
                    print(f"Input: Hello, how are you?")
                    print(f"Output: {generated}")
                else:
                    print(result)
                
                print("-" * 70)
                print()
                print("🎉 Your API key is working! You can now use real AI responses.")
                
            elif response.status_code == 503:
                print("⏳ Model is loading...")
                print()
                print("This is normal for the first request.")
                print("Wait 30-60 seconds and run this script again.")
                
            elif response.status_code == 404:
                print(f"❌ Model '{model}' not found!")
                print()
                print("Try one of these models instead:")
                print("  - gpt2")
                print("  - gpt2-medium")
                print("  - EleutherAI/gpt-neo-1.3B")
                print()
                print("Update LLM_MODEL in .env file")
                
            elif response.status_code == 401:
                print("❌ Invalid API key!")
                print()
                print("Check your HUGGINGFACE_API_KEY in .env file")
                print("Get a new key: https://huggingface.co/settings/tokens")
                
            else:
                print(f"❌ Error: {response.status_code}")
                print()
                print("Response:")
                print(response.text)
                
    except httpx.TimeoutException:
        print("❌ Request timed out!")
        print()
        print("The model might be too large or slow.")
        print("Try using 'gpt2' model first.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print()
        print("Check your internet connection and API key.")
    
    print()
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_huggingface_api())
