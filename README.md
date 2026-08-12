# AI Scanner

**LLM-guided automated web-application scanner for Burp Suite Professional.**

## Description

AI Scanner automatically tests websites from a blackbox perspective assisted by an LLM. It will try to cover as much surface as possible: crawling, authenticating, registering, following links, analyzing JavaScript, identyfing API specs, etc. The purpose is to drive the native Burp active scans to those endpoints/parameters to deterministacally assess a webapp. 

It may use Burp AI or a local model to find potential routes and triage decisions (specially when testing other LLM models). 

![AI Scanner running against a target — the Agent tab shows live progress, confirmed findings, and the grounded chat.](docs/screenshot.png)

## Features

- **Autonomous authentication** — form login/registration, JSON/JWT APIs, OpenAPI spec-driven token bootstrap
  (learns the auth-header name + login operation from the app's own spec), and **OAuth2 password-grant**
  (harvests `client_id`/`client_secret` from the page). It can also take **operator-supplied credentials** or a
  **cookie/bearer you paste in**. To reach the authenticated surface on its own it may try **common default
  credentials**, a generic **SQLi auth-bypass**, and **register a disposable-email account**. Re-authenticates
  if a crawl logs it out, and applies app security settings where relevant (e.g. DVWA security level).
- **Source-assisted mode (SAST → DAST)** — point it at the target's source repo (local path or a GitHub/GitLab
  URL it fetches itself, no `git` needed; nested source archives are unpacked) and an LLM analysis maps hidden
  routes, parameters, and sinks that a black-box crawl can't reach (`agentic` or `coarse` mode). These hints
  only **steer** discovery/probes — the deterministic oracles still decide every finding, so source hints add
  coverage but never a false positive.
- **Deep endpoint discovery** — JS/HTML mining, deterministic `/api/vN/` harvesting, LLM-inferred routes,
  SPA-route→API resolution, and OpenAPI/Swagger ingestion (`$ref` + Swagger 2.0/OpenAPI 3.0), with a site-map
  bridge so all probes see the recovered endpoints. Optional **headless-browser driver** (Playwright) drives a
  real browser through Burp's proxy to capture JS-rendered surface.
- **Deterministic, zero-FP probes** (each confirmed by an oracle, not a guess):
  - NoSQL injection — operator/`$where`, JSON-value operator injection, and JSON authentication-bypass
  - Blind SQL injection (boolean + time)
  - OS command injection (time-based) and server-side **`eval`/SSJS code execution** (arithmetic oracle)
  - Reflected XSS (with WAF-evasion variants)
  - Path traversal / LFI, open redirect, SSRF and out-of-band (blind) XXE via Burp Collaborator
  - Insecure deserialization, GraphQL abuse, and CSRF
  - Mass assignment → privilege escalation (confirmed by decoding the returned JWT/principal)
  - IDOR / broken object-level authorization, BFLA, and privilege-parity (privileged data via an ungated sibling)
  - Unauthenticated access to protected endpoints and OAuth2 authorization-server flaws (redirect_uri/token leak)
  - JWT weaknesses (`alg=none`, missing expiry, disclosed/weak signing key) and webhook signature fail-open
  - Sensitive-data exposure (cleartext secrets in responses, incl. secrets embedded in JWT payloads)
- **Multi-step agentic flows** — an LLM planner chains requests (create→consume, auth→privileged action) and
  replays values leaked by one probe into sibling endpoints the crawler never reached, to reach stateful vulns.
- **WAF-evasion mode** (optional toggle) — probes also send obfuscated payload variants so a signature WAF that
  blocks the naive payload lets the equivalent one through. It automatically backs off rate-limiting apps.
- **Findings as native Burp Audit Issues**, deduplicated, scope-gated, with multi-request evidence.
- **Chat assistant** grounded in the current scope, scan log, and findings.

## Benchmark: DAST vs DAST + SAST

Findings per target, **black-box (DAST)** vs the same scan with **source-assisted mode (DAST + SAST)**. The extension reads the target's source repo to discover/probe, while the
deterministic oracles still decide every finding, so hints only add coverage.

Tested usiong **Qwen 3.6 35b** as the LLM backend. Findings = native audit issues + our own confirmed
`VULNERABILITY` oracles (`VULNERABILITY:` / `HIGH` / `MED`).

| Target | DAST | DAST + SAST | Δ |
|---|---:|---:|---:|
| webgoat | TBC | TBC | TBC |
| xvna | TBC | TBC | TBC |
| dvws | TBC | TBC | TBC |
| juice | TBC | TBC | TBC |
| snapstore | TBC | TBC | TBC |
| sqli-labs | TBC | TBC | TBC |
| dvwa | TBC | TBC | TBC |
| vapi | TBC | TBC | TBC |
| mutillidae | TBC | TBC | TBC |
| dvna | TBC | TBC | TBC |
| tiredful | TBC | TBC | TBC |
| wackopicko | TBC | TBC | TBC |
| vulnerableapp | TBC | TBC | TBC |
| dvoauth | TBC | TBC | TBC |
| reactvulna | TBC | TBC | TBC |
| aiptlab | TBC | TBC | TBC |
| **Total** | **TBC** | **TBC** | **TBC** |

The largest gains are on apps whose vulnerable surface a black-box crawl can't reach on its own.

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
