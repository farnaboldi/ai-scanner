# AI Scanner

**LLM-guided automated web-application scanner for Burp Suite Professional.**

## Description

AI Scanner automatically tests websites from a blackbox perspective assisted by an LLM. It will try to cover as much surface as possible: crawling, authenticating, registering, following links, analyzing JavaScript, identyfing API specs, etc. The purpose is to drive the native Burp active scans to those endpoints/parameters to deterministacally assess a webapp. 

It may use Burp AI or a local model to find potential routes and triage decisions (specially when testing other LLM models). 

![AI Scanner running against a target — the Agent tab shows live progress, confirmed findings, and the grounded chat.](docs/screenshot.png)

## Features

- **Autonomous authentication** — form login/registration, JSON/JWT APIs, and spec-driven token bootstrap
  (learns the auth-header name + login operation from the app's own OpenAPI spec). To reach the authenticated
  surface it may **try common default credentials** on the login and **register a disposable-email account**.
- **Deep endpoint discovery** — JS/HTML mining + OpenAPI/Swagger ingestion (`$ref` + Swagger 2.0/OpenAPI 3.0),
  with a site-map bridge so all probes see the recovered endpoints.
- **Deterministic, zero-FP probes** (each confirmed by an oracle, not a guess):
  - NoSQL injection (operator/`$where`, plus JSON auth-bypass)
  - Blind SQL injection (boolean + time)
  - Mass assignment → privilege escalation (confirmed by decoding the returned JWT/principal)
  - IDOR / broken object-level authorization
  - Broken function-level authorization (BFLA) and privilege-parity (privileged data via an ungated sibling)
  - Unauthenticated access to protected endpoints
  - Sensitive-data exposure (cleartext secrets in responses, incl. secrets embedded in JWT payloads)
  - Path traversal / LFI, open redirect, out-of-band (blind) XXE via Burp Collaborator
- **WAF-evasion mode** (optional toggle) — probes also send obfuscated payload variants so a signature WAF that
  blocks the naive payload lets the equivalent one through. It will automatically to deal with rate-limiting apps.
- **Findings as native Burp Audit Issues**, deduplicated, scope-gated, with multi-request evidence.
- **Chat assistant** grounded in the current scope, scan log, and findings.

## Requirements

- **Burp Suite Professional** (active scanning is Pro-only).
- An AI backend — either:
  - **Burp AI**
  - a **local/self-hosted OpenAI-compatible** server (vLLM, llama.cpp, Ollama, LM Studio, …).
- Detection is deterministic, so the core scan still runs **without any AI** (useful for air-gapped networks);
  the AI only improves target discovery and triage.

## Usage

1. **Configure the AI provider** — open the **AI Scanner** tab → **Settings**:
   - *Burp AI (built-in)* — nothing to configure; just make sure Burp AI is enabled.
   - *Local / self-hosted LLM* — enter the Base URL (`…/v1`), model, and (optional) API key, then **Test
     connection**.
2. **Run a scan** — right-click a host or request (Site map / Proxy history / Target) → **"Crawl and scan this
   host"**. AI Scanner authenticates, crawls, discovers, and audits automatically.
3. **Watch progress** in the AI Scanner tab (**Agent** view / log). Confirmed vulnerabilities appear in Burp's
   **Dashboard** and **site-map issues** as `AI: …` audit issues, with the proving requests attached.
4. *(Optional)* Enable **WAF evasion mode** in Settings when testing behind a signature WAF.

### Command line (headless)

You can run it from the CLI to auto crawl and scan a target with:

```bash
AISCANNER_BASE_URL="http://127.0.0.1:8000/v1/" \
AISCANNER_MODEL="your-model" \
AISCANNER_API_KEY="sk-…" \
AISCANNER_REPORT_DIR="/tmp/ai-scanner" \
./ai-scanner.sh http://zero.webappsecurity.com/
```

## Privacy & data handling

- With **Burp AI**, prompts go through Burp's own AI plumbing — no data is sent to an endpoint the extension
  chose.
- With a **local LLM**, request/response context is sent only to the endpoint **you** configure.
- All target HTTP traffic goes through Burp's own HTTP stack (honoring your proxy/upstream settings). The only
  non-target request is to a public disposable-email service, used to complete registration when the scan
  needs a fresh account.

## Building

Standard Maven build (the montoya-api is provided by Burp at runtime; org.json is shaded in):

```bash
mvn -B -DskipTests package
# → target/ai-scanner-0.1.0.jar   (load this in Burp: Extensions → Add → Java)
```

## Author

Fernando Arnaboldi
