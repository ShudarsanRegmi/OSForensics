"""ReAct-pattern investigation agent backed by the Gemini API.

Architecture
------------
    User query
        ↓
    InvestigationAgent.run()   ← ReAct loop
        ↓
    LLM (Gemini) → {thought, action, args}
        ↓
    agent_tools.execute_tool()
        ↓
    agent_memory  (episode + evidence store)
        ↓
    LLM receives observation → next step  (repeat)
        ↓
    LLM → {action: "ANSWER", answer: "..."}

The run() method is a generator that yields event dicts so the API layer
can stream them to the frontend via SSE as they happen.

Setup
-----
    pip install google-generativeai
    export GEMINI_API_KEY="your-api-key-here"
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Generator, List, Optional, Tuple

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from . import agent_memory as memory
from . import agent_tools as tools

# ── Gemini configuration ───────────────────────────────────────────────────────

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyDMYOze-eeaG3PmG213b9gIvKkcR8YMxsw")
DEFAULT_MODEL  = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")
MAX_OBS_CHARS  = 4000   # truncate large tool outputs before re-feeding to LLM

# ── Rate-limit / retry config ──────────────────────────────────────────────────
_RETRY_MAX      = int(os.environ.get("GEMINI_RETRY_MAX",      "4"))   # attempts
_RETRY_BASE_SEC = float(os.environ.get("GEMINI_RETRY_BASE",  "5.0"))  # initial back-off
_RETRY_CAP_SEC  = float(os.environ.get("GEMINI_RETRY_CAP", "120.0"))  # max back-off

# Safety settings — relaxed for forensics/security content so tool output
# describing malware, exploits, etc. is not blocked.
_SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HARASSMENT:        HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH:       HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM = """\
You are an expert digital forensics investigator embedded in an OS forensics workstation.
You systematically gather and analyse digital evidence to identify security incidents,
malware persistence, unauthorised access, and suspicious activity.

## AVAILABLE TOOLS
{tool_list}

## INVESTIGATION PROTOCOL
Work like a real forensic investigator:
1. Understand the investigation goal
2. Choose the most relevant tool to collect evidence
3. Analyse the results critically — look for anomalies, IOCs, and patterns
4. Build a chain of evidence before drawing conclusions
5. Cite specific values (file paths, PIDs, IPs, timestamps) in your answer

## RESPONSE FORMAT
Respond ONLY with a valid JSON object — no markdown, no prose outside the JSON.

When you need to call a tool:
{{
  "thought": "Your reasoning: what evidence you need and why this tool",
  "action": "tool_name",
  "args": {{"param": "value"}}
}}

When you have enough evidence to answer:
{{
  "thought": "Summary of everything gathered",
  "action": "ANSWER",
  "answer": "Detailed forensic findings with specific evidence citations and IOCs"
}}

## CONSTRAINTS
- Always use at least one tool before answering
- Be specific — cite actual data values from tool results
- If a tool returns an error, try an alternative approach or explain the limitation
- Maximum {max_steps} investigation steps, then provide your best analysis
"""


def _build_tool_list() -> str:
    lines = []
    for name, t in tools.TOOL_REGISTRY.items():
        params = ", ".join(f"{k}: {v}" for k, v in t["params"].items())
        lines.append(f"  {name}({params})\n    → {t['description']}")
    return "\n".join(lines)


def _system_prompt(max_steps: int) -> str:
    return _SYSTEM.format(tool_list=_build_tool_list(), max_steps=max_steps)


# ── Gemini helpers ─────────────────────────────────────────────────────────────

def _build_client() -> genai.GenerativeModel:
    """Configure the Gemini SDK and return a GenerativeModel instance."""
    if not GEMINI_API_KEY:
        raise EnvironmentError(
            "GEMINI_API_KEY environment variable is not set. "
            "Get a key at https://aistudio.google.com/app/apikey"
        )
    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel(
        model_name=DEFAULT_MODEL,
        safety_settings=_SAFETY_SETTINGS,
        generation_config=genai.types.GenerationConfig(
            temperature=0.1,
            max_output_tokens=2048,
        ),
    )


def _parse_retry_after(exc: Exception) -> Optional[float]:
    """Extract the retry-after delay (seconds) from a 429 exception, if present.

    Gemini embeds the value in the error message as e.g.
    'Please retry in 34.106330841s.'
    """
    m = re.search(r"retry in\s+([\d.]+)\s*s", str(exc), re.IGNORECASE)
    return float(m.group(1)) if m else None


def _is_rate_limit(exc: Exception) -> bool:
    """Return True when *exc* is a Gemini 429 / quota-exceeded error."""
    msg = str(exc).lower()
    return "429" in msg or "quota" in msg or "rate" in msg


def _gemini_chat(
    history: List[dict],
    system: str,
    model_instance: genai.GenerativeModel,
) -> str:
    """Send a full conversation to Gemini and return the assistant text.

    Automatically retries on 429 rate-limit errors using exponential back-off
    (capped at _RETRY_CAP_SEC).  The Gemini error message often embeds an exact
    'retry in Xs' delay which is used directly when present.

    Gemini's Python SDK uses a slightly different message format than OpenAI/Ollama:
      - roles must be "user" or "model"  (not "assistant")
      - the system instruction is passed at model-construction time OR prepended
        as the first user turn; here we inject it as a leading user/model pair
        so no special constructor argument is needed.

    Args:
        history:        List of {"role": "user"|"model", "parts": [str]} dicts.
        system:         The system-prompt string (injected as the first exchange).
        model_instance: A configured GenerativeModel.

    Returns:
        The assistant's raw text response.
    """
    gemini_history = [
        {"role": "user",  "parts": [system]},
        {"role": "model", "parts": ['{"thought":"Understood. I am ready to begin the forensic investigation.","action":"READY"}']},
    ] + history

    last_exc: Exception = RuntimeError("No attempts made")
    wait = _RETRY_BASE_SEC

    for attempt in range(1, _RETRY_MAX + 1):
        try:
            chat = model_instance.start_chat(history=gemini_history[:-1])
            response = chat.send_message(gemini_history[-1]["parts"])
            return response.text
        except Exception as exc:
            last_exc = exc
            if not _is_rate_limit(exc) or attempt == _RETRY_MAX:
                raise

            suggested = _parse_retry_after(exc)
            delay = suggested if suggested is not None else min(wait, _RETRY_CAP_SEC)
            # Small buffer so we don't hit the limit again immediately
            delay = min(delay + 1.0, _RETRY_CAP_SEC)
            wait  = min(wait * 2, _RETRY_CAP_SEC)   # exponential for next attempt
            time.sleep(delay)

    raise last_exc


def _to_gemini_role(role: str) -> str:
    """Map OpenAI-style roles to Gemini roles."""
    return "model" if role == "assistant" else role


def _messages_to_gemini(messages: List[dict]) -> List[dict]:
    """Convert {"role": ..., "content": str} list to Gemini format.

    Skips the system message (index 0) — it is handled separately.
    """
    return [
        {"role": _to_gemini_role(m["role"]), "parts": [m["content"]]}
        for m in messages
        if m["role"] != "system"
    ]


# ── JSON parsing (unchanged from Ollama version) ───────────────────────────────

def _sanitize_escapes(text: str) -> str:
    r"""Remove backslashes before characters that are not valid JSON escape targets.

    LLMs commonly emit  \'  inside JSON strings, which is illegal in JSON.
    Valid JSON escape sequences are: \" \\ \/ \b \f \n \r \t \uXXXX.
    Anything else (e.g. \' \! \,) has its backslash dropped.
    """
    return re.sub(r'\\([^"\\/bfnrtu\n\r]|u(?![0-9a-fA-F]{4}))', r'\1', text)


def _parse_json(text: str) -> dict:
    """Extract and parse the JSON object from an LLM response."""
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
        fragment = text[start:]
        healed = _heal_json(fragment)
        try:
            return json.loads(healed)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON in LLM response: {text[:300]!r}")


def _heal_json(fragment: str) -> str:
    """Best-effort: close unclosed strings and braces in a truncated JSON object."""
    in_string           = False
    escape              = False
    depth               = 0
    last_colon_pos      = -1
    last_complete_pos   =  0
    open_string_is_val  = False
    last_non_ws         = ""

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
                    last_complete_pos = i + 1
                last_non_ws = ch
            elif ch == ",":
                if depth == 1:
                    last_complete_pos = i + 1
                last_non_ws = ch
            elif ch == ":":
                if depth == 1:
                    last_colon_pos = i
                last_non_ws = ch
            elif not ch.isspace():
                last_non_ws = ch

    if depth <= 0:
        return fragment

    result   = fragment + ('"' if in_string else "")
    stripped = result.rstrip()
    last_char = stripped[-1] if stripped else ""

    def _close(base: str) -> str:
        base = base.rstrip().rstrip(",")
        return (base if base else "{") + "}" * depth

    if last_char == ":":
        return _close(stripped[:last_complete_pos])
    if in_string and not open_string_is_val:
        return _close(stripped[:last_complete_pos])
    return _close(stripped)


def _truncate(data: Any, max_chars: int = MAX_OBS_CHARS) -> str:
    s = json.dumps(data, default=str)
    if len(s) > max_chars:
        return s[:max_chars] + f"… [truncated {len(s) - max_chars} chars]"
    return s


# ── Agent ──────────────────────────────────────────────────────────────────────

class InvestigationAgent:
    def __init__(self, model: str = DEFAULT_MODEL, max_steps: int = 6):
        self.model     = model
        self.max_steps = max_steps
        self._client: Optional[genai.GenerativeModel] = None

    def _get_client(self) -> genai.GenerativeModel:
        """Lazily initialise and cache the Gemini client."""
        if self._client is None:
            self._client = _build_client()
        return self._client

    # ── Gemini health / model listing ─────────────────────────────────────────

    def check_ollama(self) -> Tuple[bool, str]:
        """Compatibility shim — checks the Gemini API instead of Ollama.

        Returns (available: bool, model_name_or_error_message: str).
        Named 'check_ollama' to preserve the existing API contract; callers
        that display "Ollama" in their UI may want to rename this.
        """
        try:
            if not GEMINI_API_KEY:
                return False, "GEMINI_API_KEY is not set"
            genai.configure(api_key=GEMINI_API_KEY)
            available = [m.name for m in genai.list_models()
                         if "generateContent" in m.supported_generation_methods]
            if not available:
                return False, "No Gemini models available for this API key"
            # Use requested model if available, otherwise fall back to first
            preferred = [m for m in available if self.model in m]
            self.model = preferred[0].replace("models/", "") if preferred else available[0].replace("models/", "")
            self._client = None   # force re-init with (possibly) updated model name
            return True, self.model
        except Exception as e:
            return False, f"Gemini API error ({type(e).__name__}): {e}"

    def list_models(self) -> List[str]:
        """Return the list of Gemini models that support content generation."""
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            return [
                m.name.replace("models/", "")
                for m in genai.list_models()
                if "generateContent" in m.supported_generation_methods
            ]
        except Exception:
            return []

    # ── ReAct loop ─────────────────────────────────────────────────────────────

    def run(
        self,
        query: str,
        session_id: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        """Execute the ReAct investigation loop.

        Yields event dicts (suitable for SSE serialisation):
          {"type": "session",  "session_id": str}
          {"type": "step",     "step": int, "thought": str, "action": str,
                               "args": dict, "observation": dict}
          {"type": "answer",   "text": str, "session_id": str, "steps": int}
          {"type": "error",    "message": str}
        """
        if session_id is None:
            session_id = memory.create_session(query)
        yield {"type": "session", "session_id": session_id}

        try:
            client = self._get_client()
        except EnvironmentError as e:
            yield {"type": "error", "message": str(e)}
            return

        system = _system_prompt(self.max_steps)

        # We maintain messages in OpenAI-style dicts internally; they are
        # converted to Gemini format per-call inside _gemini_chat.
        messages: List[dict] = [
            {"role": "system", "content": system},
            {"role": "user",   "content": query},
        ]

        for step in range(1, self.max_steps + 1):

            # ── LLM call (with transparent rate-limit retry) ───────────────────
            raw = None
            for attempt in range(1, _RETRY_MAX + 1):
                try:
                    gemini_history = _messages_to_gemini(messages)
                    raw    = _gemini_chat(gemini_history, system, client)
                    parsed = _parse_json(raw)
                    break   # success
                except Exception as exc:
                    if _is_rate_limit(exc) and attempt < _RETRY_MAX:
                        suggested = _parse_retry_after(exc)
                        delay = min((suggested or _RETRY_BASE_SEC * attempt) + 1.0, _RETRY_CAP_SEC)
                        yield {
                            "type":    "waiting",
                            "reason":  "rate_limit",
                            "seconds": delay,
                            "attempt": attempt,
                            "message": f"Rate limit hit — waiting {delay:.0f}s before retry ({attempt}/{_RETRY_MAX - 1})",
                        }
                        time.sleep(delay)
                    else:
                        yield {"type": "error", "message": f"Step {step} LLM error: {exc}"}
                        return
            else:
                # All retries exhausted inside _gemini_chat — already raised
                return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            # Skip the synthetic READY action emitted during warm-up
            if action == "READY":
                continue

            # ── Final answer ───────────────────────────────────────────────────
            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                memory.add_episode(session_id, step, thought, "ANSWER", {}, {"answer": answer})
                yield {
                    "type": "answer",
                    "text": answer,
                    "session_id": session_id,
                    "steps": step,
                }
                return

            if not action:
                yield {"type": "error", "message": f"Step {step}: LLM returned no action."}
                return

            # ── Tool execution ─────────────────────────────────────────────────
            observation = tools.execute_tool(action, args)
            memory.add_episode(session_id, step, thought, action, args, observation)
            memory.store_evidence(session_id, action, observation, source=str(args))

            yield {
                "type":        "step",
                "step":        step,
                "thought":     thought,
                "action":      action,
                "args":        args,
                "observation": observation,
            }

            # Feed truncated observation back for the next LLM call.
            # Gemini uses "model" for the assistant role.
            obs_str = _truncate(observation)
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"Tool '{action}' result:\n{obs_str}\n\n"
                    "Continue the investigation. If you have gathered enough "
                    "evidence, provide your ANSWER now. Otherwise call the next "
                    "appropriate tool."
                ),
            })

        # ── Max steps reached: force final answer ──────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                "You have reached the maximum investigation steps. "
                "Provide your final forensic analysis based on all evidence gathered. "
                'Respond with JSON: {"thought": "...", "action": "ANSWER", "answer": "..."}'
            ),
        })
        try:
            gemini_history = _messages_to_gemini(messages)
            raw    = _gemini_chat(gemini_history, system, client)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "Investigation complete.")
            yield {
                "type": "answer",
                "text": answer,
                "session_id": session_id,
                "steps": self.max_steps,
            }
        except Exception as e:
            yield {"type": "error", "message": f"Failed to generate final answer: {e}"}


# ── Module-level singleton ─────────────────────────────────────────────────────

_agent: Optional[InvestigationAgent] = None


def get_agent() -> InvestigationAgent:
    global _agent
    if _agent is None:
        _agent = InvestigationAgent()
    return _agent