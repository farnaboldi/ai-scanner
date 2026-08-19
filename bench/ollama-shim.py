#!/usr/bin/env python3
"""
ollama-shim — a tiny native-Ollama API facade that forwards to an OpenAI-compatible
endpoint (our local qwen at 127.0.0.1:8000), so apps hardcoded to the Ollama wire protocol
can reuse the model we already run. Pure stdlib, no deps.

Why: AspGoat (Program.cs) builds an OllamaSharp OllamaApiClient against
    http://host.docker.internal:11434   (when DOTNET_RUNNING_IN_CONTAINER=true)
    http://localhost:11434              (otherwise)
so running this shim on the HOST's :11434 lights up AspGoat's LLM labs with no app
patch — the container reaches host.docker.internal:11434 → this shim → qwen.

Routes implemented (the subset OllamaSharp actually calls):
    GET  /                → ok banner
    GET  /api/version     → {"version": ...}
    GET  /api/tags        → advertise the served model(s)
    POST /api/show        → minimal model metadata
    POST /api/generate    → {prompt[,system]} → /v1/chat/completions
    POST /api/chat        → {messages[]}       → /v1/chat/completions
generate/chat honor "stream" (NDJSON when true — OllamaSharp streams by default).

Config via env (all optional):
    SHIM_PORT        listen port                 (default 11434)
    SHIM_HOST        listen addr                 (default 0.0.0.0)
    OPENAI_BASE      upstream base, /v1          (default http://127.0.0.1:8000/v1)
    OPENAI_MODEL     model id to send upstream    (default qwen3.6-35b)
    OPENAI_API_KEY   Bearer key                   (default from a known local key)
    OPENAI_NO_THINK  "1" → append /no_think + strip <think> (Qwen)  (default 1)
"""
import json, os, re, sys, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT      = int(os.environ.get("SHIM_PORT", "11434"))
HOST      = os.environ.get("SHIM_HOST", "0.0.0.0")
BASE      = os.environ.get("OPENAI_BASE", "http://127.0.0.1:8000/v1").rstrip("/")
MODEL     = os.environ.get("OPENAI_MODEL", "qwen3.6-35b")
API_KEY   = os.environ.get("OPENAI_API_KEY", os.environ.get("AISCANNER_API_KEY", ""))
NO_THINK  = os.environ.get("OPENAI_NO_THINK", "1") == "1"
MAX_TOK   = int(os.environ.get("OPENAI_MAX_TOKENS", "512"))   # cap output length — verbose code-gen otherwise
                                                              # runs a scan's LLM-fuzz phase to tens of minutes
# Advertise whatever the caller asks for AS WELL AS our real model, so a client that
# validates its SelectedModel against /api/tags is satisfied regardless of aiModel.
ADVERTISE = [m for m in [MODEL, "tinyllama:1.1b-chat"] if m]

_THINK = re.compile(r"<think>.*?</think>", re.S)


def _one_call(messages, temperature, max_tokens):
    """A single OpenAI /chat/completions call → assistant text (thinking stripped)."""
    body = {"model": MODEL, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens, "stream": False}
    if NO_THINK:
        # Qwen3/vLLM: disable the reasoning trace via the chat template (NOT a "/no_think" string suffix — that
        # pollutes the prompt and leaks into generated content). Mirrors the extension's LocalAiEngine.
        body["chat_template_kwargs"] = {"enable_thinking": False}
    req = urllib.request.Request(BASE + "/chat/completions", data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("ngrok-skip-browser-warning", "1")   # harmless off-ngrok; required when BASE is an ngrok tunnel
    if API_KEY:
        req.add_header("Authorization", "Bearer " + API_KEY)
    with urllib.request.urlopen(req, timeout=120) as r:
        obj = json.loads(r.read().decode())
    text = ((obj.get("choices") or [{}])[0].get("message") or {}).get("content", "") or ""
    return _THINK.sub("", text).strip()


def _upstream_chat(messages, temperature=0.3, max_tokens=None):
    """Call upstream, retrying once on an empty reply (thinking models intermittently return empty content)."""
    if max_tokens is None:
        max_tokens = MAX_TOK
    text = _one_call(messages, temperature, max_tokens)
    if not text:
        text = _one_call(messages, min(0.8, temperature + 0.4), max_tokens)   # nudge temperature, try once more
    return text


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        sys.stderr.write("[shim] " + (a[0] % a[1:]) + "\n")

    def _send(self, code, obj, ndjson_lines=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/x-ndjson" if ndjson_lines else "application/json")
        self.end_headers()
        if ndjson_lines is not None:
            for line in ndjson_lines:
                self.wfile.write((json.dumps(line) + "\n").encode())
        else:
            self.wfile.write(json.dumps(obj).encode())

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path.startswith("/api/version"):
            return self._send(200, {"version": "0.1.0-shim"})
        if self.path.startswith("/api/tags"):
            models = [{"name": m, "model": m, "modified_at": "2026-01-01T00:00:00Z",
                       "size": 0, "digest": "sha256:0", "details": {"family": "qwen"}}
                      for m in ADVERTISE]
            return self._send(200, {"models": models})
        return self._send(200, {"status": "ollama-shim → " + BASE + " (" + MODEL + ")"})

    def do_POST(self):
        b = self._body()
        stream = bool(b.get("stream", True))  # OllamaSharp streams by default
        try:
            if self.path.startswith("/api/show"):
                return self._send(200, {"license": "", "modelfile": "", "parameters": "",
                                        "template": "", "details": {"family": "qwen"}})
            if self.path.startswith("/api/generate"):
                msgs = []
                if b.get("system"):
                    msgs.append({"role": "system", "content": b["system"]})
                msgs.append({"role": "user", "content": b.get("prompt", "")})
                text = _upstream_chat(msgs)
                if stream:
                    return self._send(200, None, ndjson_lines=[
                        {"model": MODEL, "response": text, "done": False},
                        {"model": MODEL, "response": "", "done": True, "done_reason": "stop"},
                    ])
                return self._send(200, {"model": MODEL, "response": text, "done": True,
                                        "done_reason": "stop"})
            if self.path.startswith("/api/chat"):
                msgs = b.get("messages") or []
                text = _upstream_chat([{"role": m.get("role", "user"),
                                        "content": m.get("content", "")} for m in msgs])
                if stream:
                    return self._send(200, None, ndjson_lines=[
                        {"model": MODEL, "message": {"role": "assistant", "content": text}, "done": False},
                        {"model": MODEL, "message": {"role": "assistant", "content": ""}, "done": True,
                         "done_reason": "stop"},
                    ])
                return self._send(200, {"model": MODEL,
                                        "message": {"role": "assistant", "content": text},
                                        "done": True, "done_reason": "stop"})
        except urllib.error.HTTPError as e:
            return self._send(502, {"error": "upstream HTTP %d: %s" % (e.code, e.reason)})
        except Exception as e:
            return self._send(502, {"error": "shim error: %s" % e})
        return self._send(404, {"error": "unhandled route " + self.path})


if __name__ == "__main__":
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write("[shim] listening on %s:%d → %s (model=%s, no_think=%s)\n"
                     % (HOST, PORT, BASE, MODEL, NO_THINK))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
