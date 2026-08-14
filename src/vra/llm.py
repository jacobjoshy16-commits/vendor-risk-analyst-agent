"""Local model access via Ollama, with a deterministic offline backend.

Two backends, one interface:

* ``OllamaBackend``  — talks to a local Ollama daemon. The intended production
  path. No vendor risk data leaves the workstation.
* ``OfflineBackend`` — a deterministic rule-based stand-in used by ``--offline``,
  by CI, and by anyone evaluating the repo without pulling a 7B model. It is
  NOT a model: it is a small heuristic that returns the same JSON shape so the
  pipeline and the tests are runnable end to end. Output is labelled
  ``backend: offline-heuristic`` everywhere it appears, including the report,
  so nobody mistakes a heuristic result for a model result.

Every prompt and response goes to data/llm_audit.jsonl (Phase 3.5), including
failed and retried attempts. Auditability is the point: if a reviewer asks
"what exactly did you ask the model", the answer is a file.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import LLM_AUDIT_LOG, RunConfig


class SecretInPromptError(RuntimeError):
    """Raised when a raw credential would reach the language-model layer."""


_SECRET_IN_PROMPT = re.compile(
    r"(?:SSWS\s+\S+|Bearer\s+[A-Za-z0-9._\-]{20,}|xox[baprs]-[A-Za-z0-9-]+|"
    r"client_secret\s*[:=]\s*\S+|api_token\s*[:=]\s*\S+)",
    re.I,
)


def assert_prompt_clean(*parts: str) -> None:
    blob = "\n".join(p or "" for p in parts)
    hit = _SECRET_IN_PROMPT.search(blob)
    if hit:
        raise SecretInPromptError(
            "refusing to send a raw credential to the language model: "
            + hit.group(0)[:24] + "…"
        )


@dataclass
class LLMResult:
    ok: bool
    data: dict[str, Any]
    raw: str
    backend: str
    model: str
    attempts: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def audit(record: dict[str, Any], *, path: Path = LLM_AUDIT_LOG) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# JSON extraction — models wrap JSON in prose and fences no matter what you ask
# ---------------------------------------------------------------------------
def extract_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    candidates = []
    if fence:
        candidates.append(fence.group(1))
    candidates.append(text)
    for candidate in candidates:
        candidate = candidate.strip()
        start = candidate.find("{")
        while start != -1:
            depth, in_str, esc = 0, False, False
            for idx in range(start, len(candidate)):
                ch = candidate[idx]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        blob = candidate[start : idx + 1]
                        try:
                            parsed = json.loads(blob)
                            if isinstance(parsed, dict):
                                return parsed
                        except json.JSONDecodeError:
                            break
            start = candidate.find("{", start + 1)
    return None


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class Backend:
    name = "base"

    def generate(self, system: str, prompt: str, cfg: RunConfig) -> tuple[str, str | None]:
        raise NotImplementedError


class OllamaBackend(Backend):
    name = "ollama"

    def generate(self, system: str, prompt: str, cfg: RunConfig) -> tuple[str, str | None]:
        try:
            import requests
        except ImportError:
            return "", "requests not installed"
        url = f"{cfg.ollama_host.rstrip('/')}/api/generate"
        payload = {
            "model": cfg.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "format": "json",  # Ollama-side JSON forcing
            "options": {"temperature": 0.0, "num_ctx": 8192, "seed": 7},
        }
        try:
            resp = requests.post(url, json=payload, timeout=180)
            resp.raise_for_status()
            return resp.json().get("response", ""), None
        except Exception as exc:
            return "", f"ollama call failed: {exc}"


class OfflineBackend(Backend):
    """Deterministic heuristic stand-in. Explicitly not a model.

    Kept honest on purpose: it applies keyword rules to the diff text and
    returns the same schema the model must return. It exists so the repo is
    runnable and testable with no daemon and no weights.
    """

    name = "offline-heuristic"

    AGENT_TERMS = (
        "without requiring administrator approval",
        "without human approval",
        "without approval",
        "agent mode",
        "autonomous",
        "acts on your behalf",
        "end to end",
        "per-action approval is not available",
    )
    WRITE_TERMS = (
        "creates, modifies",
        "deactivates",
        "revokes",
        "modify records",
        "write access",
        "assigns and removes",
    )
    NEW_AI_TERMS = ("copilot", "assist", "ai ", "generative", "model", "llm", "summariz")
    PROVIDER_TERMS = (
        "openai", "anthropic", "perplexity", "cohere", "mistral", "google llc",
        "azure openai", "bedrock", "vertex ai", "hugging face", "inflection", "xai",
    )
    RETENTION_TERMS = ("retention", "retained for", "deleted after")
    TRAINING_TERMS = ("train", "training", "fine-tune", "fine tune")

    def generate(self, system: str, prompt: str, cfg: RunConfig) -> tuple[str, str | None]:
        # The task is embedded in the prompt; dispatch on the marker the
        # prompt builders insert.
        if "TASK: AI_RELEVANCE_TRIAGE" in prompt:
            return json.dumps(self._triage(prompt)), None
        if "TASK: FINDING_NARRATIVE" in prompt:
            return json.dumps(self._narrative(prompt)), None
        if "TASK: VENDOR_OUTREACH" in prompt:
            return json.dumps(self._outreach(prompt)), None
        if "TASK: BOOTSTRAP_REGISTER" in prompt:
            return json.dumps(self._bootstrap(prompt)), None
        return json.dumps({}), "offline backend: unknown task"

    # -- triage -----------------------------------------------------------
    def _triage(self, prompt: str) -> dict[str, Any]:
        added = re.findall(r"^\+(?!\+\+)(.*)$", prompt, re.MULTILINE)
        added_text = "\n".join(added)
        low = added_text.lower()

        def excerpt(terms: tuple[str, ...]) -> str:
            for line in added:
                if any(t in line.lower() for t in terms):
                    return line.strip()[:500]
            return added[0].strip()[:500] if added else ""

        agentic = any(t in low for t in self.AGENT_TERMS)
        writes = any(t in low for t in self.WRITE_TERMS)
        provider_hit = [p for p in self.PROVIDER_TERMS if p in low]
        is_subproc_source = "source: subprocessors" in prompt.lower()

        if agentic and writes:
            return {
                "ai_relevant": True,
                "change_type": "new_agent",
                "summary": (
                    "Vendor changelog announces an agent mode that performs directory and session "
                    "changes directly without per-action administrator approval."
                ),
                "affected_fields": ["autonomy", "human_in_loop", "status"],
                "proposed_surface_update": {"autonomy": "acts", "human_in_loop": False},
                "evidence_excerpt": excerpt(self.AGENT_TERMS + self.WRITE_TERMS),
                "confidence": 0.86,
            }
        if agentic:
            return {
                "ai_relevant": True,
                "change_type": "autonomy_increase",
                "summary": "Vendor increased the autonomy of an existing AI feature.",
                "affected_fields": ["autonomy"],
                "proposed_surface_update": {"autonomy": "acts"},
                "evidence_excerpt": excerpt(self.AGENT_TERMS),
                "confidence": 0.7,
            }
        if provider_hit and is_subproc_source:
            return {
                "ai_relevant": True,
                "change_type": "new_subprocessor",
                "summary": (
                    "Subprocessor list adds a model or AI service provider not previously disclosed."
                ),
                "affected_fields": ["model_provider"],
                "proposed_surface_update": {"model_provider": "see evidence excerpt"},
                "evidence_excerpt": excerpt(tuple(provider_hit)),
                "confidence": 0.78,
            }
        if provider_hit:
            return {
                "ai_relevant": True,
                "change_type": "model_provider_change",
                "summary": "Vendor text references a change in model provider.",
                "affected_fields": ["model_provider"],
                "proposed_surface_update": {},
                "evidence_excerpt": excerpt(tuple(provider_hit)),
                "confidence": 0.6,
            }
        if any(t in low for t in self.RETENTION_TERMS) and re.search(r"\d+\s*day", low):
            return {
                "ai_relevant": True,
                "change_type": "retention_change",
                "summary": "Vendor changed a stated retention period relevant to AI features.",
                "affected_fields": ["retention_days"],
                "proposed_surface_update": {},
                "evidence_excerpt": excerpt(self.RETENTION_TERMS),
                "confidence": 0.55,
            }
        if any(t in low for t in self.TRAINING_TERMS) and "not use" not in low:
            return {
                "ai_relevant": True,
                "change_type": "training_policy_change",
                "summary": "Vendor changed language about training on customer data.",
                "affected_fields": ["training_on_customer_data"],
                "proposed_surface_update": {},
                "evidence_excerpt": excerpt(self.TRAINING_TERMS),
                "confidence": 0.5,
            }
        return {
            "ai_relevant": False,
            "change_type": "none",
            "summary": "Changes appear cosmetic or unrelated to the vendor's AI surface.",
            "affected_fields": [],
            "proposed_surface_update": {},
            "evidence_excerpt": "",
            "confidence": 0.6,
        }

    # -- narrative / outreach --------------------------------------------
    @staticmethod
    def _field(prompt: str, key: str) -> str:
        m = re.search(rf"^{re.escape(key)}:\s*(.+)$", prompt, re.MULTILINE)
        return m.group(1).strip() if m else ""

    def _bootstrap(self, prompt: str) -> dict[str, Any]:
        """Propose an initial ai_surface from FULL artifact text, not a diff."""
        low = prompt.lower()
        features: list[dict[str, Any]] = []
        for name, keys in (
            ("OpenAI", ("openai",)),
            ("Anthropic", ("anthropic",)),
            ("Perplexity", ("perplexity",)),
            ("Google", ("vertex ai", "google llc", "google cloud")),
        ):
            if any(k in low for k in keys):
                features.append({
                    "feature": f"AI service via {name}",
                    "status": "available",
                    "autonomy": "unknown",
                    "model_provider": name,
                    "human_in_loop": "unknown",
                    "training_on_customer_data": "unknown",
                    "evidence_excerpt": name,
                })
        if any(t in low for t in self.AGENT_TERMS) and features:
            features[0]["autonomy"] = "acts"
            features[0]["human_in_loop"] = False
        return {
            "features": features[:5],
            "notes": (
                "Offline heuristic proposed features from named model providers "
                "in the full artifact text. Quarantined for human review."
            ),
        }

    def _narrative(self, prompt: str) -> dict[str, Any]:
        vendor = self._field(prompt, "vendor")
        control = self._field(prompt, "control_id")
        question = self._field(prompt, "control_question")
        feature = self._field(prompt, "feature")
        severity = self._field(prompt, "severity")
        observed = self._field(prompt, "observed")
        return {
            "narrative": (
                f"{vendor}'s AI feature \"{feature}\" does not satisfy control {control}: {question} "
                f"Observed state: {observed}. This is rated {severity} under the organisation's vendor AI "
                f"control set and requires documented remediation or a formal risk acceptance."
            )
        }

    def _outreach(self, prompt: str) -> dict[str, Any]:
        vendor = self._field(prompt, "vendor")
        control = self._field(prompt, "control_id")
        question = self._field(prompt, "control_question")
        feature = self._field(prompt, "feature")
        kind = self._field(prompt, "kind")
        need = self._field(prompt, "need")
        if need:
            # The caller (analyst.draft_outreach) supplies a precise ask — e.g.
            # portal access for a blocked subprocessor parse. Honour it rather
            # than regenerating a generic request.
            ask = f"Please provide the following: {need}"
        else:
            ask = (
                "Please provide the evidence described below"
                if kind == "gap"
                else "Please confirm your remediation plan and target date"
            )
        return {
            "subject": f"Vendor NHI / agentic review — {vendor} ({feature}) — control {control}",
            "body": (
                f"Hello,\n\n"
                f"As part of continuous third-party NHI and agentic-AI monitoring (NIST SP 800-53 / SOC 2), we have identified an item "
                f"relating to {feature} in {vendor} that we need to resolve against our control "
                f"{control}.\n\n"
                f"Control question: {question}\n\n"
                f"{ask}. Specifically we require written confirmation addressing the control question "
                f"above, along with any supporting documentation (attestations, test summaries, or "
                f"contractual language) you are able to share under our existing agreement.\n\n"
                f"This item affects our assessment of customer data processed by your service and by "
                f"any non-human identity it runs in our tenants. Please respond within 21 days.\n\n"
                f"Regards,\nVendor Risk Management"
            ),
        }


def get_backend(cfg: RunConfig) -> Backend:
    return OllamaBackend() if cfg.llm_enabled else OfflineBackend()


def probe_ollama(cfg: RunConfig) -> bool:
    """True if an Ollama daemon is reachable and has the configured model."""
    if cfg.offline:
        return False
    try:
        import requests

        resp = requests.get(f"{cfg.ollama_host.rstrip('/')}/api/tags", timeout=5)
        resp.raise_for_status()
        names = {m.get("name", "") for m in resp.json().get("models", [])}
        return any(n == cfg.model or n.split(":")[0] == cfg.model.split(":")[0] for n in names)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public call with schema validation and retry (Phase 6: "Force JSON. Retry.")
# ---------------------------------------------------------------------------
def call_json(
    *,
    system: str,
    prompt: str,
    cfg: RunConfig,
    schema_check,
    task: str,
    context: dict[str, Any] | None = None,
    max_attempts: int = 3,
    backend: Backend | None = None,
) -> LLMResult:
    backend = backend or get_backend(cfg)
    call_id = str(uuid.uuid4())
    last_raw, last_err = "", None

    for attempt in range(1, max_attempts + 1):
        attempt_prompt = prompt
        if attempt > 1:
            attempt_prompt = (
                prompt
                + "\n\nYour previous response was rejected: "
                + str(last_err)
                + "\nReturn ONLY a single valid JSON object matching the schema. No prose, no code fence."
            )
        started = time.time()
        assert_prompt_clean(system, attempt_prompt)
        raw, err = backend.generate(system, attempt_prompt, cfg)
        elapsed = round(time.time() - started, 3)
        last_raw = raw

        parsed = extract_json(raw) if not err else None
        problem = err
        if parsed is None and not problem:
            problem = "no JSON object found in response"
        if parsed is not None:
            problem = schema_check(parsed)

        audit(
            {
                "call_id": call_id,
                "attempt": attempt,
                "task": task,
                "backend": backend.name,
                "model": cfg.model if backend.name == "ollama" else backend.name,
                "context": context or {},
                "system": system,
                "prompt": attempt_prompt,
                "response_raw": raw,
                "parsed_ok": problem is None,
                "error": problem,
                "elapsed_s": elapsed,
            }
        )

        if problem is None:
            return LLMResult(True, parsed, raw, backend.name, cfg.model, attempt)
        last_err = problem

    return LLMResult(False, {}, last_raw, backend.name, cfg.model, max_attempts, last_err)
