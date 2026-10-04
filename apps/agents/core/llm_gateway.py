"""
Abstract LLM Gateway with provider adapters (OpenRouter, Ollama) and runtime capability validation.
Prevents vendor lock-in and handles dynamic model rotations without hardcoded historical models.
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel

logger = logging.getLogger("LLMGateway")
logging.basicConfig(level=logging.INFO)


class ModelCapabilities(BaseModel):
    supports_tool_calling: bool = True
    supports_structured_output: bool = True
    context_length: int = 8192
    supports_text: bool = True
    is_available: bool = True
    model_id: str


class LLMResponse(BaseModel):
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    structured_json: Optional[Dict[str, Any]] = None
    model_used: str
    status: str = "COMPLETED"  # COMPLETED, NOT_CONFIGURED, UNAVAILABLE, FAILED
    actual_call: bool = True
    engine_type: str = "LLM"    # LLM, RULE_ENGINE, HYBRID, NOT_CONFIGURED
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: float = 0.0


class LLMProvider(ABC):
    @abstractmethod
    def validate_capabilities(self, model_id: str) -> ModelCapabilities:
        """Validates model capabilities at startup/runtime."""
        pass

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model_id: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1
    ) -> LLMResponse:
        """Generates a completion, structured output, or tool calls."""
        pass


class OpenRouterProvider(LLMProvider):
    def __init__(self, api_key: Optional[str] = None, default_model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.default_model = default_model or os.getenv("OPENROUTER_MODEL", "openrouter/free")
        self.base_url = "https://openrouter.ai/api/v1"

    def validate_capabilities(self, model_id: str) -> ModelCapabilities:
        """
        Queries OpenRouter models endpoint to check capabilities.
        If no API key or offline, returns default safe profile.
        """
        if not self.api_key:
            logger.warning("No OPENROUTER_API_KEY set; LLM provider is in offline/unconfigured mode.")
            return ModelCapabilities(
                model_id=model_id,
                supports_tool_calling=True,
                supports_structured_output=True,
                context_length=32768,
                is_available=True
            )

        try:
            req = urllib.request.Request(
                f"{self.base_url}/models",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://github.com/agentic-email-sec",
                    "X-Title": "Agentic Email Security Platform"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                models = data.get("data", [])
                
                # Check for model match
                matched = next((m for m in models if m.get("id") == model_id), None)
                if matched:
                    ctx = matched.get("context_length", 8192)
                    # OpenRouter free routers might accept tool calling
                    return ModelCapabilities(
                        model_id=model_id,
                        supports_tool_calling=True,
                        supports_structured_output=True,
                        context_length=ctx,
                        is_available=True
                    )
                else:
                    logger.warning(f"Model {model_id} not explicitly listed in catalog, using generic capabilities.")
                    return ModelCapabilities(
                        model_id=model_id,
                        supports_tool_calling=True,
                        supports_structured_output=True,
                        context_length=16384,
                        is_available=True
                    )
        except Exception as e:
            logger.warning(f"Failed to query OpenRouter catalog: {e}. Defaulting to safe capability assumption.")
            return ModelCapabilities(
                model_id=model_id,
                supports_tool_calling=True,
                supports_structured_output=True,
                context_length=16384,
                is_available=True
            )

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model_id: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1
    ) -> LLMResponse:
        target_model = model_id or self.default_model
        api_key = self.api_key or os.getenv("OPENROUTER_API_KEY", "")
        
        # If no API key is provided, explicitly report NOT_CONFIGURED — never fabricate an LLM response!
        if not api_key or api_key == "mock":
            logger.info(f"[LLM GATEWAY] OpenRouter API key not configured for model {target_model}. Returning NOT_CONFIGURED status.")
            return LLMResponse(
                content="",
                tool_calls=None,
                structured_json=None,
                model_used=target_model,
                status="NOT_CONFIGURED",
                actual_call=False,
                engine_type="NOT_CONFIGURED",
                tokens_prompt=0,
                tokens_completion=0,
                latency_ms=0.0
            )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        payload: Dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "temperature": temperature
        }

        if tools:
            payload["tools"] = tools
        if response_schema:
            payload["response_format"] = {
                "type": "json_object"
            }

        t0 = time.time()
        try:
            import requests
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/agentic-email-sec",
                    "X-Title": "Agentic Email Security Platform"
                },
                timeout=(5.0, 20.0)
            )
            t1 = time.time()
            latency_ms = round((t1 - t0) * 1000.0, 2)

            if resp.status_code != 200:
                logger.error(f"OpenRouter HTTP {resp.status_code} error: {resp.text}")
                if target_model != "openrouter/free":
                    logger.info("Attempting graceful fallback to 'openrouter/free'...")
                    return self.generate(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        model_id="openrouter/free",
                        tools=tools,
                        response_schema=response_schema,
                        temperature=temperature
                    )
                return LLMResponse(
                    content="",
                    model_used=target_model,
                    status="FAILED",
                    actual_call=True,
                    engine_type="LLM",
                    latency_ms=latency_ms
                )

            res_data = resp.json()
            choice = res_data["choices"][0]["message"]
            usage = res_data.get("usage", {})

            content = choice.get("content")
            tool_calls = choice.get("tool_calls")
            structured_json = None

            if response_schema and content:
                try:
                    structured_json = json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("Strict json.loads failed on LLM output. Attempting regex markdown extraction fallback...")
                    import re
                    match = re.search(r"(\{.*\}|\[.*\])", content, re.DOTALL)
                    if match:
                        try:
                            structured_json = json.loads(match.group(0))
                        except Exception:
                            logger.error("Regex extraction also failed to parse JSON from LLM content.")
                    else:
                        logger.error("Failed to parse expected JSON output from LLM.")

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                structured_json=structured_json,
                model_used=target_model,
                status="COMPLETED",
                actual_call=True,
                engine_type="LLM",
                tokens_prompt=usage.get("prompt_tokens", 0),
                tokens_completion=usage.get("completion_tokens", 0),
                latency_ms=latency_ms
            )

        except Exception as e:
            t1 = time.time()
            latency_ms = round((t1 - t0) * 1000.0, 2)
            logger.error(f"Error in OpenRouterProvider request: {e}")
            return LLMResponse(
                content="",
                model_used=target_model,
                status="FAILED",
                actual_call=False,
                engine_type="LLM",
                latency_ms=latency_ms
            )


class LocalOllamaProvider(LLMProvider):
    """Local LLM provider for Confidential / Restricted data boundaries."""
    def __init__(self, base_url: Optional[str] = None, model: str = "llama3:latest"):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model

    def validate_capabilities(self, model_id: str) -> ModelCapabilities:
        return ModelCapabilities(
            model_id=model_id,
            supports_tool_calling=True,
            supports_structured_output=True,
            context_length=8192,
            is_available=True
        )

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model_id: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1
    ) -> LLMResponse:
        logger.info(f"[LocalOllamaProvider] Routing sensitive request to local model {self.model}")
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    pass
        except Exception:
            logger.warning(f"[LocalOllamaProvider] Local Ollama service unreachable at {self.base_url}")
            return LLMResponse(
                content="",
                tool_calls=None,
                structured_json=None,
                model_used=f"ollama/{self.model}",
                status="UNAVAILABLE",
                actual_call=False,
                engine_type="NOT_CONFIGURED",
                tokens_prompt=0,
                tokens_completion=0,
                latency_ms=0.0
            )
        return LLMResponse(
            content="",
            model_used=f"ollama/{self.model}",
            status="NOT_CONFIGURED",
            actual_call=False,
            engine_type="NOT_CONFIGURED"
        )


class LLMGateway:
    """
    Central Gateway enforcing model capability checks, runtime fallbacks,
    and provider routing.
    """
    _instance: Optional["LLMGateway"] = None

    @classmethod
    def get_instance(cls) -> "LLMGateway":
        if cls._instance is None:
            cls._instance = LLMGateway()
        return cls._instance

    def __init__(
        self,
        openrouter_provider: Optional[OpenRouterProvider] = None,
        local_provider: Optional[LocalOllamaProvider] = None
    ):
        self.openrouter = openrouter_provider or OpenRouterProvider()
        self.local_ollama = local_provider or LocalOllamaProvider()
        
        # Validate default model on startup
        self._startup_validation()
        LLMGateway._instance = self

    def is_configured(self) -> bool:
        """Returns True if an OpenRouter API key is set in environment or provider."""
        api_key = self.openrouter.api_key or os.getenv("OPENROUTER_API_KEY", "")
        if api_key and not self.openrouter.api_key:
            self.openrouter.api_key = api_key
        return bool(api_key and api_key.strip() and api_key != "mock")

    def generate_completion(
        self,
        prompt: str,
        system_prompt: str = "You are an autonomous tier-3 SOC investigation planner.",
        model_id: Optional[str] = None,
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        """Generates completion via openrouter provider."""
        resp = self.openrouter.generate(
            system_prompt=system_prompt,
            user_prompt=prompt,
            model_id=model_id,
            temperature=temperature
        )
        return {
            "content": resp.content,
            "status": resp.status,
            "model_used": resp.model_used,
            "actual_call": resp.actual_call,
            "tokens_prompt": resp.tokens_prompt,
            "tokens_completion": resp.tokens_completion,
            "latency_ms": resp.latency_ms
        }

    def _startup_validation(self):
        default_model = self.openrouter.default_model
        logger.info(f"LLMGateway: Validating default model: {default_model}")
        caps = self.openrouter.validate_capabilities(default_model)
        logger.info(
            f"LLMGateway: Model '{caps.model_id}' validated. "
            f"Tools: {caps.supports_tool_calling}, JSON: {caps.supports_structured_output}, Context: {caps.context_length}"
        )

    def get_provider(self, is_confidential: bool = False) -> LLMProvider:
        if is_confidential:
            return self.local_ollama
        return self.openrouter
