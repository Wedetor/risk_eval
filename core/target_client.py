"""Client for the model under evaluation (the *target*).

The target is only ever asked to answer prompts. It never judges anything:
judging is done by an independent model (see core/judge.py).
"""
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from openai import BadRequestError, OpenAI

# Qwen3-style reasoning blocks. They are removed before judging and their
# presence is logged, so that thinking never counts as part of the answer.
_THINK_BLOCK = re.compile(r"<think>.*?(</think>|$)", re.DOTALL | re.IGNORECASE)

# Error types (anything that is not a real answer of the target model).
ERR_TARGET_EXCEPTION = "target_exception"
ERR_EMPTY_RESPONSE = "empty_response"


@dataclass
class Generation:
    text: Optional[str]                 # answer after stripping thinking blocks (None on exception)
    raw_text: Optional[str] = None      # answer exactly as returned by the server
    finish_reason: Optional[str] = None
    had_thinking: bool = False
    error_type: Optional[str] = None    # None | target_exception | empty_response
    error: Optional[str] = None
    attempts: int = 0
    latency_s: float = 0.0
    usage: dict = field(default_factory=dict)


class TargetClient:
    def __init__(self, base_url, model="Local-Model", max_tokens=512, disable_thinking=True,
                 retries=3, timeout=600):
        self.base_url = base_url
        self.model = model
        self.max_tokens = max_tokens
        self.disable_thinking = disable_thinking
        self.retries = retries
        self.client = OpenAI(base_url=base_url, api_key="sk-local-eval", timeout=timeout, max_retries=0)

    def _extra_body(self):
        if not self.disable_thinking:
            return None
        # Honoured per request by llama.cpp `llama-server --jinja` (and vLLM) for Qwen3
        # templates; ignored by other servers/models. llama-cpp-python only accepts it at
        # server start (--chat_template_kwargs). The preflight check in risk_eval.py
        # verifies that the target is really not producing reasoning.
        return {"chat_template_kwargs": {"enable_thinking": False}}

    def generate(self, prompt, temperature):
        start = time.time()
        last_err = None
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    max_tokens=self.max_tokens,
                    extra_body=self._extra_body(),
                )
                choice = resp.choices[0]
                raw = choice.message.content or ""
                reasoning = getattr(choice.message, "reasoning_content", None)
                had_thinking = bool(reasoning) or "<think>" in raw.lower()
                text = _THINK_BLOCK.sub("", raw).strip()
                usage = resp.usage.model_dump() if getattr(resp, "usage", None) else {}
                gen = Generation(
                    text=text, raw_text=raw, finish_reason=choice.finish_reason,
                    had_thinking=had_thinking, attempts=attempt,
                    latency_s=round(time.time() - start, 3), usage=usage,
                )
                if not text:
                    gen.error_type = ERR_EMPTY_RESPONSE
                    gen.error = "Target returned an empty answer"
                return gen
            except Exception as e:  # network errors, timeouts, server errors...
                last_err = e
                if isinstance(e, BadRequestError):
                    # e.g. prompt longer than the context window: retrying cannot help
                    # (Giskard's control-chars detector then retries with a shorter injection).
                    break
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
        return Generation(
            text=None, error_type=ERR_TARGET_EXCEPTION,
            error=f"{type(last_err).__name__}: {last_err}", attempts=attempt,
            latency_s=round(time.time() - start, 3),
        )
