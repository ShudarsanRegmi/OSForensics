"""Multi-Agent Orchestration Framework for OS Forensics.

Architecture
------------
    User Query
        ↓
    OrchestratorAgent.run()          ← Top-level ReAct loop
        ↓
    LLM decides which sub-agent to dispatch to
        ↓
    dispatch_to_subagent("browser_agent", task=..., path=...)
        ↓
    SubAgent.run()                   ← Domain-specialist ReAct loop
        ↓
    Domain tools (browser, memory, persistence, …)
        ↓
    SubAgent yields structured findings → Orchestrator
        ↓
    Orchestrator aggregates + synthesises a final forensic answer

Sub-Agents
----------
  browser_agent     – Chrome/Firefox history, downloads, cookies, extensions
  memory_agent      – Volatility3 memory dump analysis
  persistence_agent – Cron, systemd, shell-startup, SSH keys
  filesystem_agent  – OS detect, tool detection, deleted files, timeline
  services_agent    – System service enumeration and anomaly detection
  config_agent      – SSH, sudo, firewall, PAM security audits
  multimedia_agent  – Image/video/audio metadata, GPS, steganography
  tails_agent       – Tails OS & Tor forensics
"""
from __future__ import annotations

import json
import os
import re
import time
import traceback
from typing import Any, Dict, Generator, List, Optional, Tuple

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from . import agent_memory as mem

# ── Gemini config ──────────────────────────────────────────────────────────────

GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY", "")
DEFAULT_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash-exp")
MAX_OBS_CHARS   = 4_000
_RETRY_MAX      = int(os.environ.get("GEMINI_RETRY_MAX", "4"))
_RETRY_BASE_SEC = float(os.environ.get("GEMINI_RETRY_BASE", "5.0"))
_RETRY_CAP_SEC  = float(os.environ.get("GEMINI_RETRY_CAP", "120.0"))

_SAFETY = {
    HarmCategory.HARM_CATEGORY_HARASSMENT:        HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH:       HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

# ── Domain tool registries (imported lazily to avoid circular imports) ─────────

def _get_sub_registries() -> Dict[str, Dict]:
    """Return per-domain tool registries, imported lazily."""
    from .sub_tools import (
        BROWSER_TOOLS, MEMORY_TOOLS, PERSISTENCE_TOOLS,
        FILESYSTEM_TOOLS, SERVICES_TOOLS, CONFIG_TOOLS,
        MULTIMEDIA_TOOLS, TAILS_TOOLS,
    )
    return {
        "browser_agent":     BROWSER_TOOLS,
        "memory_agent":      MEMORY_TOOLS,
        "persistence_agent": PERSISTENCE_TOOLS,
        "filesystem_agent":  FILESYSTEM_TOOLS,
        "services_agent":    SERVICES_TOOLS,
        "config_agent":      CONFIG_TOOLS,
        "multimedia_agent":  MULTIMEDIA_TOOLS,
        "tails_agent":       TAILS_TOOLS,
    }

# ── Sub-agent descriptions for the orchestrator prompt ────────────────────────

_SUBAGENT_DESCRIPTIONS = {
    "browser_agent": (
        "Forensic analysis of web browsers. "
        "Extracts history, downloads, cookies, saved passwords, extensions "
        "from Chrome, Firefox, Brave, Tor Browser, and others."
    ),
    "memory_agent": (
        "Memory dump analysis via Volatility3. "
        "Recovers running/hidden processes, network connections, bash history, "
        "loaded kernel modules, and malware-injected regions (malfind)."
    ),
    "persistence_agent": (
        "Persistence mechanism detection. "
        "Checks crontabs, systemd service units, shell startup files "
        "(.bashrc/.profile/rc.local), and SSH authorized_keys for backdoors."
    ),
    "filesystem_agent": (
        "Filesystem-level forensics. "
        "Detects OS identity, offensive/privacy tools installed, deleted files, "
        "and builds a chronological activity timeline from filesystem timestamps."
    ),
    "services_agent": (
        "System service enumeration and anomaly detection. "
        "Lists all systemd/init services, flags unknown or suspicious ones "
        "that may represent malware persistence or tunnels."
    ),
    "config_agent": (
        "Security configuration audit. "
        "Reviews SSH daemon config, sudo rules, firewall (ufw/iptables), "
        "PAM config, sysctl kernel parameters for weaknesses."
    ),
    "multimedia_agent": (
        "Multimedia file forensics. "
        "Scans images/video/audio for EXIF metadata, embedded GPS coordinates, "
        "steganography indicators, and hidden data."
    ),
    "tails_agent": (
        "Tails OS and Tor specialised forensics. "
        "Detects amnesic boot parameters, Tor activity, onion destinations, "
        "hidden services, persistence volumes, and anti-forensic behaviour."
    ),
}

# ── Shared LLM helpers ─────────────────────────────────────────────────────────

def _build_model(model_name: str = DEFAULT_MODEL) -> genai.GenerativeModel:
    if not GEMINI_API_KEY:
        raise EnvironmentError(
            "GEMINI_API_KEY not set. Export it before running the agent."
        )
    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel(
        model_name=model_name,
        safety_settings=_SAFETY,
        generation_config=genai.types.GenerationConfig(
            temperature=0.1,
            max_output_tokens=2048,
        ),
    )


def _is_rate_limit(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "quota" in msg or "rate" in msg


def _retry_after(exc: Exception) -> Optional[float]:
    m = re.search(r"retry in\s+([\d.]+)\s*s", str(exc), re.IGNORECASE)
    return float(m.group(1)) if m else None


def _gemini_call(history: List[dict], system: str, model: genai.GenerativeModel) -> str:
    """Send history to Gemini with retry on rate-limit. Returns raw text."""
    full_history = [
        {"role": "user",  "parts": [system]},
        {"role": "model", "parts": ['{"thought":"Ready","action":"READY"}']},
    ] + history

    wait = _RETRY_BASE_SEC
    last_exc: Exception = RuntimeError("no attempts")

    for attempt in range(1, _RETRY_MAX + 1):
        try:
            chat = model.start_chat(history=full_history[:-1])
            return chat.send_message(full_history[-1]["parts"]).text
        except Exception as exc:
            last_exc = exc
            if not _is_rate_limit(exc) or attempt == _RETRY_MAX:
                raise
            delay = min((_retry_after(exc) or wait) + 1.0, _RETRY_CAP_SEC)
            wait  = min(wait * 2, _RETRY_CAP_SEC)
            time.sleep(delay)

    raise last_exc


def _to_gemini(messages: List[dict]) -> List[dict]:
    role_map = {"assistant": "model", "user": "user"}
    return [
        {"role": role_map.get(m["role"], m["role"]), "parts": [m["content"]]}
        for m in messages
        if m["role"] not in ("system",)
    ]


def _sanitize_escapes(text: str) -> str:
    return re.sub(r'\\([^"\\/bfnrtu\n\r]|u(?![0-9a-fA-F]{4}))', r'\1', text)


def _parse_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text.strip())
    text = _sanitize_escapes(text)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start != -1:
        try:
            healed = _heal_json(text[start:])
            return json.loads(healed)
        except json.JSONDecodeError:
            pass
    raise ValueError(f"No valid JSON in LLM response: {text[:300]!r}")


def _heal_json(fragment: str) -> str:
    in_string = escape = False
    depth = 0
    last_complete = 0
    last_non_ws = ""
    open_string_is_val = False

    for i, ch in enumerate(fragment):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            if not in_string:
                open_string_is_val = (last_non_ws == ":")
            in_string = not in_string
            continue
        if not in_string:
            if ch == "{":
                depth += 1
                last_non_ws = ch
            elif ch == "}":
                depth -= 1
                if depth > 0:
                    last_complete = i + 1
                last_non_ws = ch
            elif ch == ",":
                if depth == 1:
                    last_complete = i + 1
                last_non_ws = ch
            elif ch == ":":
                last_non_ws = ch
            elif not ch.isspace():
                last_non_ws = ch

    if depth <= 0:
        return fragment
    result   = fragment + ('"' if in_string else "")
    stripped = result.rstrip()
    last_c   = stripped[-1] if stripped else ""
    def _close(base: str) -> str:
        base = base.rstrip().rstrip(",")
        return (base or "{") + "}" * depth
    if last_c == ":" or (in_string and not open_string_is_val):
        return _close(stripped[:last_complete])
    return _close(stripped)


def _truncate(data: Any, max_chars: int = MAX_OBS_CHARS) -> str:
    s = json.dumps(data, default=str)
    if len(s) > max_chars:
        return s[:max_chars] + f"… [truncated {len(s) - max_chars} chars]"
    return s


# ── Sub-agent ──────────────────────────────────────────────────────────────────

_SUB_SYSTEM = """\
You are a specialist forensic sub-agent: {role_name}.

## YOUR DOMAIN
{domain_description}

## AVAILABLE TOOLS
{tool_list}

## PROTOCOL
1. Reason about what evidence to collect in this domain.
2. Call tools one at a time.
3. Once you have sufficient evidence, emit ANSWER.

## RESPONSE FORMAT (strict JSON only — no prose outside JSON)

Tool call:
{{
  "thought": "Why I need this data",
  "action":  "tool_name",
  "args":    {{"param": "value"}}
}}

Final answer:
{{
  "thought": "Summary of findings",
  "action":  "ANSWER",
  "answer":  "Detailed findings with specific evidence citations"
}}

## CONSTRAINTS
- Always use at least one tool before answering.
- Cite specific file paths, PIDs, timestamps, IPs in your answer.
- Maximum {max_steps} steps, then give best-effort answer.
- Task context: {task}
"""


class SubAgent:
    """A domain-specialist ReAct agent with a restricted tool set."""

    def __init__(
        self,
        agent_id: str,
        description: str,
        tool_registry: Dict[str, dict],
        model: genai.GenerativeModel,
        max_steps: int = 5,
    ):
        self.agent_id    = agent_id
        self.description = description
        self.tools       = tool_registry
        self.model       = model
        self.max_steps   = max_steps

    def _tool_list_str(self) -> str:
        lines = []
        for name, t in self.tools.items():
            params = ", ".join(f"{k}: {v}" for k, v in t["params"].items())
            lines.append(f"  {name}({params})\n    → {t['description']}")
        return "\n".join(lines) or "  (no tools available)"

    def _system(self, task: str) -> str:
        return _SUB_SYSTEM.format(
            role_name=self.agent_id,
            domain_description=self.description,
            tool_list=self._tool_list_str(),
            task=task,
            max_steps=self.max_steps,
        )

    def _execute(self, action: str, args: dict) -> dict:
        if action not in self.tools:
            return {"error": f"Tool '{action}' not in {self.agent_id}'s registry. "
                             f"Available: {list(self.tools)}"}
        try:
            return self.tools[action]["fn"](**args)
        except TypeError as e:
            return {"error": f"Bad args for '{action}': {e}"}
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}

    def run(
        self,
        task: str,
        session_id: str,
        parent_step: int,
    ) -> Generator[Dict, None, None]:
        """Execute domain-specific ReAct loop.

        Yields sub-step events and a final ``subagent_result`` event.
        """
        system   = self._system(task)
        messages = [{"role": "user", "content": task}]
        steps_taken = 0

        for step in range(1, self.max_steps + 1):
            # ── LLM call ────────────────────────────────────────────────────
            wait = _RETRY_BASE_SEC
            raw  = None

            for attempt in range(1, _RETRY_MAX + 1):
                try:
                    gemini_history = _to_gemini(messages)
                    raw    = _gemini_call(gemini_history, system, self.model)
                    parsed = _parse_json(raw)
                    break
                except Exception as exc:
                    if _is_rate_limit(exc) and attempt < _RETRY_MAX:
                        delay = min((_retry_after(exc) or wait) + 1.0, _RETRY_CAP_SEC)
                        wait  = min(wait * 2, _RETRY_CAP_SEC)
                        yield {
                            "type":     "subagent_waiting",
                            "agent_id": self.agent_id,
                            "seconds":  delay,
                            "attempt":  attempt,
                            "message":  f"[{self.agent_id}] Rate-limit — waiting {delay:.0f}s",
                        }
                        time.sleep(delay)
                    else:
                        yield {
                            "type":     "subagent_error",
                            "agent_id": self.agent_id,
                            "message":  f"[{self.agent_id}] LLM error at step {step}: {exc}",
                        }
                        return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            if action == "READY":
                continue

            # ── Final answer ─────────────────────────────────────────────────
            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                mem.add_episode(session_id, parent_step * 100 + step,
                                thought, "ANSWER", {}, {"answer": answer, "agent": self.agent_id})
                yield {
                    "type":       "subagent_result",
                    "agent_id":   self.agent_id,
                    "steps_taken": steps_taken,
                    "answer":     answer,
                }
                return

            if not action:
                yield {
                    "type":     "subagent_error",
                    "agent_id": self.agent_id,
                    "message":  f"[{self.agent_id}] Step {step}: no action returned.",
                }
                return

            # ── Tool call ────────────────────────────────────────────────────
            observation = self._execute(action, args)
            steps_taken += 1

            mem.add_episode(session_id, parent_step * 100 + step,
                            thought, action, args, observation)
            mem.store_evidence(session_id, f"{self.agent_id}.{action}",
                               observation, source=str(args))

            yield {
                "type":        "subagent_step",
                "agent_id":    self.agent_id,
                "step":        step,
                "thought":     thought,
                "action":      action,
                "args":        args,
                "observation": observation,
            }

            obs_str = _truncate(observation)
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"Tool '{action}' result:\n{obs_str}\n\n"
                    "Continue analysing. Provide ANSWER when you have enough evidence."
                ),
            })

        # ── Max steps: force answer ───────────────────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                "Maximum steps reached. Provide your best forensic findings now.\n"
                '{"thought":"...","action":"ANSWER","answer":"..."}'
            ),
        })
        try:
            gemini_history = _to_gemini(messages)
            raw    = _gemini_call(gemini_history, system, self.model)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "No findings.")
        except Exception as e:
            answer = f"[{self.agent_id}] Could not generate final answer: {e}"

        yield {
            "type":        "subagent_result",
            "agent_id":    self.agent_id,
            "steps_taken": steps_taken,
            "answer":      answer,
        }


# ── Orchestrator ───────────────────────────────────────────────────────────────

_ORCH_SYSTEM = """\
You are the chief forensic orchestrator. You coordinate a team of specialist
sub-agents to investigate a digital evidence source comprehensively.

## AVAILABLE SUB-AGENTS
{subagent_list}

## SPECIAL ACTION
dispatch_subagent(agent_id, task, path)
  → Dispatch a sub-agent to perform domain-specific investigation.
    agent_id : one of the agent names above
    task     : natural-language description of what you need from that agent
    path     : absolute filesystem path or dump file to investigate

## RESPONSE FORMAT (strict JSON only)

Dispatch a sub-agent:
{{
  "thought": "Why I need this domain's analysis",
  "action":  "dispatch_subagent",
  "args":    {{"agent_id": "browser_agent", "task": "...", "path": "..."}}
}}

Final synthesis (only after collecting evidence from relevant agents):
{{
  "thought": "Overall forensic picture",
  "action":  "ANSWER",
  "answer":  "Comprehensive forensic report citing all sub-agent findings"
}}

## ORCHESTRATION RULES
- Decompose the user query into domain-specific sub-tasks.
- Dispatch agents whose domains are relevant to the query.
- You may dispatch multiple agents sequentially or re-dispatch one with a
  follow-up task if findings warrant deeper inspection.
- Synthesise ALL sub-agent answers into a cohesive forensic narrative.
- Always dispatch at least one sub-agent before answering.
- Maximum {max_steps} orchestration steps total.
- Initial investigation path: {initial_path}
"""


class OrchestratorAgent:
    """Top-level agent that decomposes a query and delegates to sub-agents."""

    def __init__(self, model_name: str = DEFAULT_MODEL, max_steps: int = 10):
        self.model_name = model_name
        self.max_steps  = max_steps
        self._model: Optional[genai.GenerativeModel] = None
        self._sub_registries: Optional[Dict[str, Dict]] = None

    # ── Lazy init ──────────────────────────────────────────────────────────────

    def _get_model(self) -> genai.GenerativeModel:
        if self._model is None:
            self._model = _build_model(self.model_name)
        return self._model

    def _get_sub_registries(self) -> Dict[str, Dict]:
        if self._sub_registries is None:
            self._sub_registries = _get_sub_registries()
        return self._sub_registries

    # ── Orchestrator system prompt ─────────────────────────────────────────────

    def _build_system(self, initial_path: str) -> str:
        lines = []
        for agent_id, desc in _SUBAGENT_DESCRIPTIONS.items():
            lines.append(f"  {agent_id}\n    {desc}")
        return _ORCH_SYSTEM.format(
            subagent_list="\n".join(lines),
            max_steps=self.max_steps,
            initial_path=initial_path,
        )

    # ── Sub-agent dispatch ─────────────────────────────────────────────────────

    def _dispatch(
        self,
        agent_id: str,
        task: str,
        path: str,
        session_id: str,
        orch_step: int,
    ) -> Generator[Dict, None, None]:
        """Create and run the requested sub-agent; yield all its events."""
        registries = self._get_sub_registries()

        if agent_id not in registries:
            yield {
                "type":    "subagent_error",
                "agent_id": agent_id,
                "message": (
                    f"Unknown sub-agent '{agent_id}'. "
                    f"Valid agents: {list(registries)}"
                ),
            }
            return

        description = _SUBAGENT_DESCRIPTIONS.get(agent_id, "Specialist forensic agent")
        sub = SubAgent(
            agent_id    = agent_id,
            description = description,
            tool_registry = registries[agent_id],
            model       = self._get_model(),
            max_steps   = 5,
        )

        # Augment task with path context
        full_task = f"{task}\n\nFilesystem/dump path: {path}"

        yield {"type": "subagent_start", "agent_id": agent_id, "task": full_task}
        yield from sub.run(full_task, session_id, parent_step=orch_step)

    # ── Main orchestration loop ────────────────────────────────────────────────

    def run(
        self,
        query: str,
        path: str = "/",
        session_id: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        """Drive the multi-agent investigation.

        Yields event dicts:
          {"type": "session",          "session_id": str}
          {"type": "orchestrator_step","step": int, "thought": str,
                                       "dispatching": str, "task": str}
          {"type": "subagent_start",   "agent_id": str, "task": str}
          {"type": "subagent_step",    "agent_id": str, "step": int,
                                       "thought": str, "action": str,
                                       "args": dict, "observation": dict}
          {"type": "subagent_result",  "agent_id": str, "answer": str}
          {"type": "subagent_waiting", "agent_id": str, "seconds": float}
          {"type": "subagent_error",   "agent_id": str, "message": str}
          {"type": "answer",           "text": str, "session_id": str, "steps": int}
          {"type": "error",            "message": str}
        """
        if session_id is None:
            session_id = mem.create_session(query)
        yield {"type": "session", "session_id": session_id}

        try:
            model = self._get_model()
        except EnvironmentError as e:
            yield {"type": "error", "message": str(e)}
            return

        system   = self._build_system(path)
        messages = [{"role": "user", "content": query}]

        # Accumulated sub-agent answers — injected back so the LLM can synthesise
        subagent_results: Dict[str, str] = {}

        for orch_step in range(1, self.max_steps + 1):

            # ── LLM call ──────────────────────────────────────────────────────
            wait = _RETRY_BASE_SEC
            raw  = None

            for attempt in range(1, _RETRY_MAX + 1):
                try:
                    gemini_history = _to_gemini(messages)
                    raw    = _gemini_call(gemini_history, system, model)
                    parsed = _parse_json(raw)
                    break
                except Exception as exc:
                    if _is_rate_limit(exc) and attempt < _RETRY_MAX:
                        delay = min((_retry_after(exc) or wait) + 1.0, _RETRY_CAP_SEC)
                        wait  = min(wait * 2, _RETRY_CAP_SEC)
                        yield {
                            "type":    "waiting",
                            "reason":  "rate_limit",
                            "seconds": delay,
                            "attempt": attempt,
                            "message": f"Orchestrator rate-limited — waiting {delay:.0f}s",
                        }
                        time.sleep(delay)
                    else:
                        yield {"type": "error", "message": f"Orchestrator LLM error at step {orch_step}: {exc}"}
                        return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            if action == "READY":
                continue

            # ── Final answer ───────────────────────────────────────────────────
            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                mem.add_episode(session_id, orch_step, thought, "ANSWER", {}, {"answer": answer})
                yield {
                    "type":       "answer",
                    "text":       answer,
                    "session_id": session_id,
                    "steps":      orch_step,
                    "agents_used": list(subagent_results.keys()),
                }
                return

            # ── Sub-agent dispatch ─────────────────────────────────────────────
            if action == "dispatch_subagent":
                agent_id   = args.get("agent_id", "")
                sub_task   = args.get("task", query)
                sub_path   = args.get("path", path)

                yield {
                    "type":       "orchestrator_step",
                    "step":       orch_step,
                    "thought":    thought,
                    "dispatching": agent_id,
                    "task":       sub_task,
                    "path":       sub_path,
                }

                mem.add_episode(session_id, orch_step, thought, "dispatch_subagent",
                                args, {"status": "dispatched"})

                sub_answer = "(no answer)"
                for event in self._dispatch(agent_id, sub_task, sub_path,
                                            session_id, orch_step):
                    yield event
                    if event.get("type") == "subagent_result":
                        sub_answer = event.get("answer", "(no answer)")

                subagent_results[agent_id] = sub_answer

                # Feed sub-agent result back to orchestrator context
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": (
                        f"Sub-agent '{agent_id}' completed.\n\n"
                        f"FINDINGS:\n{_truncate(sub_answer)}\n\n"
                        "Decide: dispatch another sub-agent for deeper coverage, "
                        "or synthesise all findings into a final ANSWER."
                    ),
                })
                continue

            # ── Unknown action ─────────────────────────────────────────────────
            yield {
                "type":    "error",
                "message": f"Orchestrator step {orch_step}: unknown action '{action}'.",
            }
            return

        # ── Max steps: force synthesis ─────────────────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                "Maximum orchestration steps reached. "
                "Synthesise all sub-agent findings into a final forensic report.\n"
                '{"thought":"...","action":"ANSWER","answer":"..."}'
            ),
        })
        try:
            gemini_history = _to_gemini(messages)
            raw    = _gemini_call(gemini_history, system, model)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "Investigation complete.")
        except Exception as e:
            answer = f"Could not generate final answer: {e}"

        yield {
            "type":        "answer",
            "text":        answer,
            "session_id":  session_id,
            "steps":       self.max_steps,
            "agents_used": list(subagent_results.keys()),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_orchestrator: Optional[OrchestratorAgent] = None


def get_orchestrator() -> OrchestratorAgent:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = OrchestratorAgent()
    return _orchestrator
