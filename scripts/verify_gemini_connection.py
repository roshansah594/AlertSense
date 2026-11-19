"""Gemini API Connection Verification Script for AlertSense.

Checks environment configuration, validates the Gemini API key,
measures round-trip latency, and confirms structured JSON schema output.

Usage:
    python scripts/verify_gemini_connection.py
"""

import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from ai_agents.gemini_service import GeminiService


def main():
    print("=" * 70)
    print(" AlertSense – Gemini API Live Connection Diagnostics")
    print("=" * 70)

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

    print(f"[*] Detected Model Configuration: {model_name}")

    if not api_key or api_key == "your_gemini_api_key_here":
        print("\n[!] GEMINI_API_KEY is NOT configured or is set to placeholder.")
        print("[!] To configure your API key:")
        print("    1. Create a '.env' file in the AlertSense root directory:")
        print("       copy .env.example .env")
        print("    2. Get a free API key at: https://aistudio.google.com/")
        print("    3. Edit .env and set GEMINI_API_KEY=AIzaSy...")
        print("\n[*] Note: AlertSense will run seamlessly in offline/fallback mode")
        print("    without an API key using deterministic algorithms.")
        print("=" * 70)
        return 0

    masked_key = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 10 else "***"
    print(f"[*] API Key Found: {masked_key}")
    print("[*] Testing live structured JSON generation...")

    service = GeminiService(api_key=api_key, model_name=model_name)
    test_instruction = "You are an automated diagnostic health checker. Respond in JSON."
    test_prompt = "Return a JSON object with: status='ok', service='AlertSense', message='Gemini connection successful'."

    start = time.time()
    data, telemetry = service.generate_json(
        system_instruction=test_instruction,
        user_prompt=test_prompt
    )
    elapsed = round(time.time() - start, 3)

    if telemetry.get("success") and data:
        print("\n[+] SUCCESS! Gemini API connected and returned valid JSON.")
        print(f"    - Round-Trip Latency: {elapsed}s")
        print(f"    - Model Used: {telemetry.get('model')}")
        print(f"    - Structured Response: {data}")
        print("\n[*] Live AI reasoning is now active for Root Cause & Reporting agents.")
    else:
        print(f"\n[-] FAILED to connect to Gemini API.")
        print(f"    - Error: {telemetry.get('error')}")
        print(f"    - Retries Attempted: {telemetry.get('retries')}")
        print("[*] AlertSense will gracefully engage deterministic baseline fallbacks.")

    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
