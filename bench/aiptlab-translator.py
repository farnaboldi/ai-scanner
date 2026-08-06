#!/usr/bin/env python3
"""OpenAI-compatible translator in front of the local LLM (vLLM + Qwen thinking-mode).

Why: aiptlab (and any stock OpenAI client) POSTs plain OpenAI /v1/chat/completions. the local LLM is vLLM serving a
Qwen "thinking" model with two quirks that break such clients:
  (1) responses come back with content=null and the answer in `reasoning` unless enable_thinking=false is sent;
  (2) vLLM requires tool_call.function.arguments to be a JSON STRING, but clients replay it as an object -> 400.
This proxy normalizes both, adds the the local LLM API key, and mirrors /v1/models — a clean OpenAI facade over the local LLM.

Run on the HOST (it resolves `the local LLM` via /etc/hosts); Docker apps reach it at host.docker.internal:PORT.
  PORT=8891 LLM_BASE=http://127.0.0.1:8000 LLM_KEY=<key> python3 aiptlab-translator.py
"""
import json, os, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LLM  = os.environ.get("LLM_BASE", "http://127.0.0.1:8000").rstrip("/")
KEY  = os.environ.get("LLM_KEY", "")
PORT = int(os.environ.get("PORT", "8891"))


def _forward(path, body_bytes, method):
    req = urllib.request.Request(LLM + path, data=body_bytes, method=method,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {KEY}"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.status, r.read()


class H(BaseHTTPRequestHandler):
    def _send(self, code, data, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models") or self.path.startswith("/v1/models"):
            try:
                code, data = _forward("/v1/models", None, "GET")
                self._send(code, data)
            except urllib.error.HTTPError as e:
                self._send(e.code, e.read())
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        if not self.path.endswith("/chat/completions"):
            self._send(404, b'{"error":"not found"}')
            return
        # (1) Qwen: turn OFF thinking so content is populated (not null with the answer in `reasoning`).
        kw = body.get("chat_template_kwargs")
        if not isinstance(kw, dict):
            kw = {}
        kw["enable_thinking"] = False
        body["chat_template_kwargs"] = kw
        # (2) vLLM: tool_call.function.arguments MUST be a JSON string, not an object.
        for msg in body.get("messages", []) or []:
            for tc in (msg.get("tool_calls") or []):
                fn = tc.get("function") or {}
                a = fn.get("arguments")
                if isinstance(a, (dict, list)):
                    fn["arguments"] = json.dumps(a)
        try:
            code, data = _forward("/v1/chat/completions", json.dumps(body).encode(), "POST")
            # (3) belt-and-suspenders: if content still came back null, fall back to reasoning.
            try:
                d = json.loads(data)
                for ch in d.get("choices", []) or []:
                    m = ch.get("message") or {}
                    if (m.get("content") in (None, "")) and m.get("reasoning"):
                        m["content"] = m["reasoning"]
                data = json.dumps(d).encode()
            except Exception:
                pass
            self._send(code, data)
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read())
        except Exception as e:
            self._send(502, json.dumps({"error": str(e)}).encode())

    def log_message(self, format, *args):  # noqa: A002 - match BaseHTTPRequestHandler signature
        pass


if __name__ == "__main__":
    print(f"translator :{PORT} -> {LLM} (enable_thinking=false, tool-arg stringify, reasoning->content)")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
