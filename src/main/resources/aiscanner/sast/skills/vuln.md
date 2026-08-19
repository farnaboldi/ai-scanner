# Vulnerability-class skills (steering only — a deterministic oracle confirms every finding)

Sections keyed `## <slug>`. Each carries the attack surface, a testing methodology, the deterministic
**Validation** (oracle) that must fire for a finding to count, and common **False positives** to avoid.
The `Validation` line is the oracle the DAST side already enforces — the model never decides.

## sqli
**Attack surface:** any param reaching a query built by concatenation/interpolation — search/filter/sort/id params, ORDER BY, LIMIT, JSON/GraphQL args, headers logged to a DB.
**Methodology:** identify the quoting context; try a syntax break then a balanced repair; boolean (1=1 vs 1=2) and time-based where blind.
**Validation:** quote-parity — baseline 2xx, a single quote breaks it (error/5xx/diff), a balanced quote recovers 2xx; OR boolean/time differential. DB-agnostic; no error string needed.
**False positives:** a generic 500 that also fires on a non-SQL junk value is NOT SQLi — require the break-then-recover asymmetry.

## nosql
**Attack surface:** JSON body/query params feeding Mongo-style filters; login objects; `$where`.
**Methodology:** inject operators (`{"$ne":null}`, `{"$gt":""}`) as the value; `$where` with a sleep for blind.
**Validation:** operator injection changes the result-set size or the auth outcome vs the scalar baseline; `$where` time delay.
**False positives:** an endpoint that echoes the operator but returns identical data is not injectable.

## idor
**Attack surface:** object lookups by a client-supplied id (`/x/{id}`, `?id=`, GraphQL `node(id)`, base64/Relay ids); numeric or guessable references.
**Methodology:** as user A, request user B's object id; compare to A's own object and to a non-existent id (control).
**Validation:** the other object's record (with owner/PII markers) is returned, shape matches own-object and differs from the non-existent control — a differential between privilege states, never a judgment about public data.
**False positives:** public-by-design data; an empty array or a 200 with no cross-tenant fields is NOT IDOR.

## bfla
**Attack surface:** privileged actions/functions (admin endpoints, state-changing verbs) reachable by a lower role.
**Methodology:** call the admin/function endpoint with a low-priv session; compare to unauth (denied) and to a junk endpoint (404) control.
**Validation:** unauth is denied AND our low-priv session is NOT denied AND the response differs from the junk control.
**False positives:** an endpoint that returns the same to everyone; a 200 that is actually an error page.

## mass-assignment
**Attack surface:** create/update bodies bound to a model (DTO/serializer/`fill`/strong-params) that includes privileged fields (role, is_admin, balance, id, owner).
**Methodology:** add the privileged field to the request body; re-read the object / decode the returned token.
**Validation:** the privileged field actually changed — confirmed in a follow-up read or in the decoded JWT/principal.
**False positives:** the server echoes the field but did not persist it — confirm via a fresh read, not the write response.

## path-traversal
**Attack surface:** params naming a file/template/path (`file=`, `path=`, `page=`, `template=`, download/include features).
**Methodology:** depth-saturated `../` toward a known OS file; also encoded and null-byte variants.
**Validation:** an OS-file signature (`root:x:0:0:` / win.ini markers) appears in the response and not the baseline; OR path reflection resolves like the baseline for a valid sibling and fails for junk.
**False positives:** an app-level 404 / "not found" that echoes the path is not disclosure.

## command-injection
**Attack surface:** params reaching exec/spawn/shell (ping/convert/export/pdf/backup features), filenames passed to tools.
**Methodology:** shell metacharacters around a sleep or an arithmetic marker; also argument injection.
**Validation:** a time delay proportional to the payload, OR a computed arithmetic result (e.g. 8161*7919) appears unencoded and absent from the baseline.
**False positives:** a reflected payload with no execution; latency unrelated to the sleep — verify with two different durations.

## ssrf
**Attack surface:** params holding a URL/host/port (webhook, fetch, import-from-url, image proxy, pdf render).
**Methodology:** point at a Collaborator/OOB host; try internal IPs / cloud metadata (169.254.169.254).
**Validation:** an out-of-band DNS/HTTP callback to our unique Collaborator domain (server-side). No callback ≠ safe (blind).
**False positives:** a client-side redirect; a callback from a shared resolver/CDN — correlate the unique subdomain.

## xxe
**Attack surface:** endpoints accepting XML/SOAP/SVG/DOCX (Content-Type xml), SAML assertions.
**Methodology:** an external DTD entity pointing at a Collaborator URL; parameter entities for blind exfil.
**Validation:** an OOB interaction during parse (Collaborator). Deterministic by construction.
**False positives:** XML rejected before parsing — require the callback.

## deserialization
**Attack surface:** cookies/params/bodies carrying serialized blobs (Java `rO0`, PHP `O:`, Python pickle, .NET), remember-me tokens.
**Methodology:** a gadget forcing an OOB lookup (URLDNS), or an error-vs-success delta.
**Validation:** an OOB callback during `readObject`/unserialize; OR a valid-blob→200 vs corrupt-stream→500 delta.
**False positives:** an opaque token that is not deserialized (HMAC'd/random) — require the delta or callback.

## open-redirect
**Attack surface:** `redirect` / `return` / `next` / `url` / `continue` params; post-login/logout redirects.
**Methodology:** set the param to an off-origin absolute URL (and a protocol-relative `//evil`).
**Validation:** a 3xx whose Location is the attacker origin (or the page navigates there).
**False positives:** the value is reflected but the redirect stays same-origin / allow-listed.

## xss
**Attack surface:** any param reflected into an HTML/JS/attribute/URL context — search, error messages, profile fields.
**Methodology:** classify the reflection context; break out of it; place a unique marker in an executable position.
**Validation:** the marker lands unencoded in an executable context (Burp active audit / headless DOM), not inside a comment or a text-only node.
**False positives:** reflection that is HTML-encoded or confined to a non-executing context.
