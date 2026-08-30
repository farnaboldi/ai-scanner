# Framework skills (steering only — the deterministic oracle still decides every finding)

Sections are keyed `## <slug>`. Each says WHERE routes / params / sinks / auth live in that stack, so the
source analyzer can name real attacker-reachable inputs instead of re-deriving the framework every call.
Generic by ecosystem — never per-application.

## django
**Routes:** `urls.py` `urlpatterns` via `path()` / `re_path()`; DRF `router.register(...)` (ViewSets) and `@api_view`. Path converters (`<int:pk>`, `<slug:...>`) name captured params.
**Params:** `request.GET` / `request.POST` / `request.query_params` / `request.data`; view kwargs (`pk`, `id`); DRF serializer fields.
**Sinks:** `.raw()`, `.extra()`, `RawSQL`, `cursor.execute(f"...")` (SQLi); `os.system` / `subprocess` (cmd); `pickle.loads` / `yaml.load` (deser); template `|safe` / `mark_safe` / `render_template_string` (XSS/SSTI); `open()` / `FileResponse` on a user path (LFI).
**Auth:** `LoginRequiredMixin` / `@login_required`; DRF `permission_classes`. A ViewSet with `AllowAny` (or no `IsAuthenticated`/object permission) that looks up by raw `pk` is an IDOR/BFLA candidate.

## flask-fastapi
**Routes:** Flask `@app.route` / blueprint `@bp.route`; FastAPI `@app.get/post`, `APIRouter`. Path params in the decorator (`/items/{id}`).
**Params:** Flask `request.args/form/json/values`; FastAPI — CRITICAL: query/path params are declared as TYPED FUNCTION ARGUMENTS (e.g. `async def endpoint(param_name: str = "", other: int = 0, current_user=Depends(...))`). The `param_name` and `other` are HTTP query params; arguments with `Depends(...)` or `Annotated[..., Depends(...)]` are dependency injections (NOT HTTP params). Emit `paramName=param_name` for the injectable function args. Body params use `BaseModel` Pydantic schemas — field names are the param names.
**Sinks:** raw f-string SQL or `text("..." + x)` (SQLi); `subprocess.check_output/Popen` with `shell=True` (CMDi — CRITICAL: the function arg value is injected directly into the shell command); `render_template_string` / Jinja `{{ }}` on user data (SSTI); `pickle` / `yaml.load` (deser); `send_file` / `open()` on a user path (LFI); `requests.get(user_url)` / `httpx.get(user_url)` (SSRF — the function arg value is passed directly as the URL).
**Auth:** FastAPI `Depends()` vs `Security()` — a route with no auth dependency is unauthenticated by default; Pydantic models accepting extra fields → mass-assignment.

## express-node
**Routes:** `app.get/post/put/delete(...)`, `router.<verb>(...)`. Middleware ORDER matters — an auth middleware mounted after a route leaves it unprotected.
**Params:** `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`. The real key is the property read (`req.query.id` → `id`), never the accessor word.
**Sinks:** string-concatenated `db.query` / `sequelize.query` / knex `.raw` (SQLi); Mongo `{$where}` / user-built filter (NoSQL); `child_process.exec` / `execSync` (cmd); `res.redirect(user)` (open redirect); `eval` / `Function` (code); `fs` / `res.sendFile` on a user path (LFI); `axios/fetch(user_url)` (SSRF).
**Auth:** JWT middleware; routes declared before the auth middleware; object lookups by `req.params.id` with no ownership check (IDOR).

## spring
**Routes:** `@GetMapping` / `@PostMapping` / `@RequestMapping` on `@RestController` / `@Controller`.
**Params:** `@RequestParam`, `@PathVariable`, `@RequestBody` (DTOs — extra fields → mass-assignment), `@RequestHeader`.
**Sinks:** `createQuery` / `createNativeQuery` / `Statement` with concatenation (SQLi); `Runtime.getRuntime().exec` / `ProcessBuilder` (cmd); `new File(user)` / `Files.` (LFI); `readObject` / `ObjectInputStream` (deser); `DocumentBuilderFactory` / SAX without secure processing (XXE); `RestTemplate` / `WebClient` on a user URL (SSRF).
**Auth:** `@PreAuthorize` / `@Secured`, `SecurityConfig` matchers. `findById(id)` returned to any authenticated user → IDOR; a missing method-level check → BFLA.

## laravel
**Routes:** `routes/web.php`, `routes/api.php` via `Route::get/post/...` and resource controllers.
**Params:** `$request->input/query/all`, route-model binding (`{user}`), form-request classes.
**Sinks:** `DB::raw` / `whereRaw` / `DB::select("...".$x)` (SQLi); `exec` / `shell_exec` / `Process` (cmd); Blade `{!! $x !!}` (XSS); `unserialize` (deser); `Storage` / `file_get_contents` on a user path (LFI).
**Auth:** `auth` middleware, `Gate` / `Policy`; `$model->fill($request->all())` or an over-broad `$fillable` → mass-assignment; model binding returning others' records → IDOR.

## rails
**Routes:** `config/routes.rb` (`resources`, `get/post`), controller actions.
**Params:** `params[:x]`; strong-params `permit(...)` (missing/over-broad → mass-assignment).
**Sinks:** `where("... #{x}")` / `find_by_sql` / `exists?("...")` (SQLi); `system` / backticks / `%x()` / `Open3` (cmd); `Marshal.load` / `YAML.load` (deser); `send` / `constantize` / `public_send` on user data (RCE-ish); `render inline:` / `html_safe` (XSS); `send_file` / `File.read` (LFI).
**Auth:** `before_action :authenticate_user!` / Pundit / CanCanCan; an action with no authorize call plus `Model.find(params[:id])` → IDOR/BFLA.

## wordpress
**Routes:** Plugin routes register via `add_action('wp_ajax_ACTION', 'handler')` (authenticated) and `add_action('wp_ajax_nopriv_ACTION', 'handler')` (unauthenticated). Both are served at `/wp-admin/admin-ajax.php?action=ACTION`. CRITICAL: embed the action value directly in the `path` field as a query parameter (e.g. `path=/wp-admin/admin-ajax.php?action=ajaxTrigger`), NOT as a separate `paramName` — the `action` value is a fixed routing constant, not an injection target. The `paramName` should be the actual data parameter the handler reads. REST API routes via `register_rest_route('ns','pattern',...)` are served at `/wp-json/ns/v1/pattern`. Direct PHP plugin files under `wp-content/plugins/PLUGIN/file.php` are accessible at that URL path.
**CRITICAL — method selection:** Use `GET` when the handler reads `$_GET['param']`; use `POST` when it reads `$_POST['param']` or `file_get_contents('php://input')`. This determines where the scanner places the parameter — URL query string vs request body. Most search/query AJAX handlers (e.g. ajaxTrigger, ajaxInfiniteScroll) read `$_GET` and must use GET. Upload/import/save handlers read `$_POST` and must use POST.
**Default search param:** WordPress's native and plugin search parameter is `s` (e.g. `/?s=query`, `admin-ajax.php?action=ajaxTrigger&s=query`). Use `s` as the paramName for search AJAX handlers unless the code explicitly reads a different key.
**Params:** `$_GET['x']` (use method=GET); `$_POST['x']` (use method=POST); `$_REQUEST['x']` (prefer GET); raw body via `file_get_contents('php://input')` / `$HTTP_RAW_POST_DATA` (custom plugin protocols, IWP, Jetpack — use POST).
**Sinks:** `$wpdb->query/get_results/get_row/get_var/get_col` with string concatenation (SQLi — `->prepare()` is safe, raw concat is not); `unserialize/maybe_unserialize` on untrusted input (deser); `shell_exec/passthru/proc_open/system` (cmd); `file_get_contents(user_url)` (SSRF); `readfile/include(user_path)` (LFI); `move_uploaded_file` (upload).
**Auth:** `wp_ajax_nopriv_*` actions = zero authentication required. `current_user_can('edit_posts')` / `check_ajax_referer` are the guards — their ABSENCE means unauthenticated access. `is_admin()` returns true inside `/wp-admin/` requests but is NOT a security check.

## graphql
**Surface:** one `/graphql` (also `/graphiql`, `/api/graphql`) endpoint; the SCHEMA (typeDefs/SDL) and RESOLVERS are the real surface — every Query/Mutation field and every resolver ARGUMENT is an insertion point a REST crawl never sees.
**Methodology:** run introspection (`__schema`) to harvest types/fields/args; map each resolver arg to the sink it reaches (DB filter, file path, HTTP call); test injection THROUGH args (SQLi/NoSQL/cmd); test object access via `node`/`id` args (IDOR/BOLA); check mutations for mass-assignment (input types with privileged fields) and missing per-resolver authz.
**Amplification:** aliasing + batched queries multiply one request (rate-limit/DoS); deep/circular fragments.
**Auth:** authz is PER-RESOLVER — a field with no guard is BFLA; introspection enabled in prod is disclosure.
