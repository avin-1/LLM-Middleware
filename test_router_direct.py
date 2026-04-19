"""Test Router API directly"""
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.environ["HF_TOKEN"],
)

print("Testing...")
completion = client.chat.completions.create(
    model="openai/gpt-oss-120b:fireworks-ai",
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)

print("Completion:", completion)
print("Message:", completion.choices[0].message)
print("Content:", completion.choices[0].message.content)
