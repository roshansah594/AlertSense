"""Gemini API Client and Resilience Service.

Provides a robust, centralized wrapper around the Google GenAI SDK:
- Safe API key initialization from environment or runtime config.
- Bounded retries with exponential backoff for rate limits (HTTP 429) and transient errors.
- Schema enforcement and JSON markdown stripping.
- Graceful degradation: never crashes the workflow on API exhaustion.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class GeminiAPIException(Exception):
    """Raised when Gemini API encounters a non-recoverable error."""
    pass


class GeminiService:
    """Production-grade wrapper for Google Gemini API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        max_retries: int = 2,
        initial_backoff_seconds: float = 1.0,
        timeout_seconds: int = 25
    ):
        # Fix: Respect explicitly passed api_key (even if empty string)
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = (os.getenv("GEMINI_API_KEY") or "").strip()

        if model_name is not None:
            self.model_name = model_name.strip()
        else:
            self.model_name = (os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()

        self.max_retries = max_retries
        self.initial_backoff_seconds = initial_backoff_seconds
        self.timeout_seconds = timeout_seconds
        self._client = None

        if self.is_configured():
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize google-genai Client: {e}")
                self._client = None

    def is_configured(self) -> bool:
        """Return True if a valid non-placeholder API key is present."""
        return bool(
            self.api_key
            and self.api_key.lower() not in {"your_gemini_api_key_here", "none", "placeholder", ""}
            and len(self.api_key) > 10
        )

    def generate_json(
        self,
        system_instruction: str,
        user_prompt: str,
        temperature: float = 0.1
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Execute structured JSON generation with bounded retries and error handling.

        Returns:
            (parsed_json_dict, execution_telemetry)
        """
        telemetry: Dict[str, Any] = {
            "model": self.model_name,
            "success": False,
            "retries": 0,
            "latency_seconds": 0.0,
            "error": None
        }

        if not self.is_configured() or not self._client:
            telemetry["error"] = "api_key_not_configured"
            return None, telemetry

        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            temperature=temperature
        )

        start_time = time.time()
        backoff = self.initial_backoff_seconds

        for attempt in range(self.max_retries + 1):
            telemetry["retries"] = attempt
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=[user_prompt],
                    config=config
                )

                raw_text = response.text or ""
                clean_text = self._sanitize_json_markdown(raw_text)
                parsed_data = json.loads(clean_text)

                if not isinstance(parsed_data, dict):
                    raise ValueError(f"Expected JSON object, got {type(parsed_data).__name__}")

                telemetry["success"] = True
                telemetry["latency_seconds"] = round(time.time() - start_time, 3)
                return parsed_data, telemetry

            except json.JSONDecodeError as jde:
                logger.warning(f"Gemini returned invalid JSON (Attempt {attempt + 1}): {jde}")
                telemetry["error"] = f"malformed_json: {jde}"
                if attempt == self.max_retries:
                    break

            except Exception as e:
                err_str = str(e).lower()
                is_rate_limit = "429" in err_str or "quota" in err_str or "resource_exhausted" in err_str
                is_transient = "503" in err_str or "500" in err_str or "timeout" in err_str or is_rate_limit

                logger.warning(f"Gemini call error on attempt {attempt + 1}: {e}")
                telemetry["error"] = str(e)

                if is_transient and attempt < self.max_retries:
                    time.sleep(backoff)
                    backoff *= 2.0
                else:
                    break

        telemetry["latency_seconds"] = round(time.time() - start_time, 3)
        return None, telemetry

    @staticmethod
    def _sanitize_json_markdown(text: str) -> str:
        """Strip markdown code fence blocks and extract JSON object."""
        clean = text.strip()
        # Look for markdown code fence ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean)
        if fence_match:
            clean = fence_match.group(1).strip()
        else:
            # If no fences, find the outermost { ... } or [ ... ]
            json_match = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", clean)
            if json_match:
                clean = json_match.group(1).strip()

        return clean.strip()
