"""AI provider layer for CyberShield.

Supports:
- OpenRouter (remote, recommended when an API key is configured)
- Any OpenAI-compatible endpoint
- Ollama (local/offline fallback)

The provider is intentionally transport-only: security decisions remain in
CyberShield's evidence-first security layers.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LLMResult:
    ok: bool
    text: str = ""
    provider: str = "local"
    error: str | None = None


class LLMProvider:
    """Unified LLM gateway with OpenRouter-first auto routing and Ollama fallback."""

    OPENROUTER_BASE = "https://openrouter.ai/api/v1"
    OPENROUTER_FREE_MODEL = "openrouter/free"

    def __init__(self) -> None:
        self._load_dotenv()

        self.provider = os.getenv("CYBERSHIELD_AI_PROVIDER", "ollama").strip().lower()
        self.model = os.getenv("CYBERSHIELD_AI_MODEL", "openrouter/free").strip()
        self.base_url = os.getenv("CYBERSHIELD_AI_BASE_URL", "").strip().rstrip("/")
        self.api_key = os.getenv(
            "CYBERSHIELD_AI_API_KEY",
            os.getenv("OPENROUTER_API_KEY", os.getenv("OPENAI_API_KEY", "")),
        ).strip()
        self.timeout = float(os.getenv("CYBERSHIELD_AI_TIMEOUT", "30"))
        self.app_name = os.getenv("CYBERSHIELD_APP_NAME", "CyberShield").strip() or "CyberShield"
        self.app_url = os.getenv("CYBERSHIELD_APP_URL", "").strip()

        # In auto mode, a configured OpenRouter key gets priority over local AI.
        # This makes the desktop assistant useful immediately while retaining
        # Ollama as a no-network fallback.
        if self.provider == "auto" and self.api_key:
            self.provider = "openrouter"

    @staticmethod
    def _load_dotenv() -> None:
        """Load a minimal .env file without adding a third-party dependency."""
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parents[2] / ".env",
        ]
        for path in candidates:
            if not path.is_file():
                continue
            try:
                for raw in path.read_text(encoding="utf-8").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    if key and key not in os.environ:
                        os.environ[key] = value
                return
            except OSError:
                continue

    def _remote_configured(self) -> bool:
        if not self.api_key:
            return False
        return bool(self.base_url or self.provider == "openrouter")

    def available(self) -> bool:
        if self.provider == "none":
            return False
        if self.provider == "ollama":
            return bool(self._ollama_models())
        if self.provider == "openrouter":
            return self._remote_configured()
        if self.provider in {"openai", "openai_compatible", "remote"}:
            return bool(self.api_key and self.base_url)
        return bool(self._ollama_models()) or self._remote_configured()

    def ask(self, system: str, user: str) -> LLMResult:
        if self.provider == "none":
            return LLMResult(False, provider="disabled", error="disabled")

        if self.provider == "ollama":
            return self._ollama(system, user)

        if self.provider == "openrouter":
            remote = self._openrouter(system, user)
            if remote.ok:
                return remote
            local = self._ollama(system, user)
            if local.ok:
                return local
            return remote

        if self.provider in {"openai", "openai_compatible", "remote"}:
            return self._openai(system, user)

        # auto/no explicit provider: remote first when configured, then local.
        if self._remote_configured():
            remote = self._openrouter(system, user) if not self.base_url else self._openai(system, user)
            if remote.ok:
                return remote
        return self._ollama(system, user)

    def _ollama(self, system: str, user: str) -> LLMResult:
        models = self._ollama_models()
        model = self.model or "llama3.1:8b"
        if model == self.OPENROUTER_FREE_MODEL or model.endswith(":free"):
            model = "llama3.1:8b"
        if models and model not in models:
            model = models[0]
        if not models:
            return LLMResult(False, provider="ollama", error="Ollama is not running or no local model is installed")

        payload = {
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {
                "temperature": 0.10,
                "num_ctx": 12288,
                "top_p": 0.90,
                "repeat_penalty": 1.10,
            },
        }
        try:
            data = self._post("http://127.0.0.1:11434/api/chat", payload, None)
            text = str(data.get("message", {}).get("content", "")).strip()
            return LLMResult(bool(text), text, f"ollama:{model}", None if text else "empty response")
        except Exception as exc:
            return LLMResult(False, provider="ollama", error=str(exc))

    def _openrouter(self, system: str, user: str) -> LLMResult:
        """Call OpenRouter using its OpenAI-compatible Chat Completions API."""
        model = self.model or self.OPENROUTER_FREE_MODEL
        base = self.base_url or self.OPENROUTER_BASE
        endpoint = base if base.endswith("/chat/completions") else base + "/chat/completions"
        payload = {
            "model": model,
            "temperature": 0.15,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {
            "HTTP-Referer": self.app_url,
            "X-Title": self.app_name,
        }
        try:
            data = self._post(endpoint, payload, self.api_key, extra_headers=headers)
            text = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
            used_model = str(data.get("model") or model)
            return LLMResult(bool(text), text, f"openrouter:{used_model}", None if text else "empty response")
        except Exception as exc:
            return LLMResult(False, provider="openrouter", error=self._friendly_error(exc))

    def _openai(self, system: str, user: str) -> LLMResult:
        base = self.base_url or "https://api.openai.com/v1"
        endpoint = base if base.endswith("/chat/completions") else base + "/chat/completions"
        payload = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            data = self._post(endpoint, payload, self.api_key)
            text = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
            return LLMResult(bool(text), text, "openai_compatible", None if text else "empty response")
        except Exception as exc:
            return LLMResult(False, provider="openai_compatible", error=self._friendly_error(exc))

    @staticmethod
    def _friendly_error(exc: Exception) -> str:
        if isinstance(exc, urllib.error.HTTPError):
            try:
                body = exc.read().decode("utf-8", errors="replace")[:500]
                data = json.loads(body)
                message = data.get("error", {}).get("message") or data.get("message")
                if message:
                    return f"HTTP {exc.code}: {message}"
            except Exception:
                pass
            return f"HTTP {exc.code}: API request failed"
        return str(exc)

    def _ollama_models(self) -> list[str]:
        """Return installed local model names without requiring an API key."""
        try:
            req = urllib.request.Request("http://127.0.0.1:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=0.9) as response:
                data = json.loads(response.read().decode("utf-8"))
            names: list[str] = []
            for item in data.get("models", []):
                name = str(item.get("name") or item.get("model") or "").strip()
                if name and name not in names:
                    names.append(name)
            return names
        except Exception:
            return []

    def status(self) -> dict[str, Any]:
        models = self._ollama_models()
        return {
            "provider": self.provider,
            "configured_model": self.model,
            "local_available": bool(models),
            "installed_models": models,
            "remote_configured": bool(self.api_key and (self.base_url or self.provider == "openrouter")),
            "openrouter_configured": bool(self.api_key),
            "openrouter_base_url": self.OPENROUTER_BASE,
            "remote_priority_in_auto": bool(self.api_key),
        }

    def _probe(self, url: str) -> bool:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=0.8):
                return True
        except Exception:
            return False

    def _post(
        self,
        url: str,
        payload: dict[str, Any],
        api_key: str | None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = "Bearer " + api_key
        if extra_headers:
            headers.update({k: v for k, v in extra_headers.items() if v})
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))
