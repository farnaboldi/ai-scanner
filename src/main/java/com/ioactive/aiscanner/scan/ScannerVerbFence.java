package com.ioactive.aiscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ScanTask;
import com.ioactive.aiscanner.ui.ScanLog;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fail-closed DELETE/PATCH/MERGE fence for traffic that Burp's OWN scanner sends (crawl and native audit,
 * {@link ToolType#SCANNER}). {@link SafeHttp} gates every request this extension sends itself, but a crawl or audit we
 * launch is executed by Burp: with default crawl settings it submits forms, clicks every clickable element (a SPA's
 * delete button fires a DELETE XHR) and crawls the operations of any API definition it finds, using our
 * authenticated session. Montoya gives no per-task attribution, so while the fence is up it covers ALL scanner
 * traffic to ANY host (a SPA's cross-origin API calls are scanner traffic too). Proxy, Repeater, Intruder and
 * extension traffic are never touched.
 *
 * <p>Lifetime: the fence is registered while a crawl+scan job is open OR while any Burp task we launched may still
 * send. Every crawl/audit we start is {@link #track tracked}; a task leaves the set only when WE delete it (normal
 * crawl stop, {@link #deleteTracked} on Stop, or on unload). Burp's statusMessage() is unsupported on current builds,
 * so an audit left running for late findings keeps the fence up until it is deleted or AI Scanner unloads — the safe
 * side. A refused request is answered with a spoofed 405 and never sent (Burp 2026.8+), else dropped, else (an old
 * Montoya without either) rewritten to a body-less OPTIONS of the same path.
 */
public final class ScannerVerbFence implements HttpHandler {

    private static final ScannerVerbFence INSTANCE = new ScannerVerbFence();

    private final Set<ScanTask> tasks = ConcurrentHashMap.newKeySet();
    private int windows;                       // guarded by INSTANCE
    private boolean lingerNoted;               // guarded by INSTANCE
    private volatile Registration reg;
    private volatile MontoyaApi api;
    private volatile ScanLog log;

    private ScannerVerbFence() { }

    public static void init(MontoyaApi api, ScanLog scanLog) { INSTANCE.api = api; INSTANCE.log = scanLog; }

    /** Open a crawl+scan window; returns how many windows are now open. Pair with {@link #close()} in a finally. */
    public static int open() {
        synchronized (INSTANCE) {
            INSTANCE.windows++;
            INSTANCE.lingerNoted = false;
            INSTANCE.ensureRegisteredLocked();
            return INSTANCE.windows;
        }
    }

    /** Close a window. The fence stays up while a tracked task may still send. */
    public static void close() {
        synchronized (INSTANCE) {
            if (INSTANCE.windows > 0) INSTANCE.windows--;
            if (INSTANCE.windows == 0 && !INSTANCE.tasks.isEmpty() && !INSTANCE.lingerNoted) {
                INSTANCE.lingerNoted = true;
                INSTANCE.note("[verb-guard] " + INSTANCE.tasks.size() + " Burp task(s) started by AI Scanner may still "
                        + "be running — Burp's scanner keeps refusing DELETE/PATCH/MERGE until they are deleted "
                        + "(Stop) or AI Scanner is unloaded.");
            }
            INSTANCE.maybeDeregisterLocked();
        }
    }

    /** Register a crawl/audit we just started; the fence stays up while it is tracked. Returns the task. */
    public static <T extends ScanTask> T track(T task) {
        if (task == null) return null;
        INSTANCE.tasks.add(task);
        synchronized (INSTANCE) { INSTANCE.ensureRegisteredLocked(); }
        return task;
    }

    /** We deleted this task ourselves, so it can no longer send. */
    public static void untrack(ScanTask task) {
        if (task == null) return;
        INSTANCE.tasks.remove(task);
        synchronized (INSTANCE) { INSTANCE.maybeDeregisterLocked(); }
    }

    /** Delete every task we launched (Stop / unload): left alive they would keep sending once the fence is gone. */
    public static int deleteTracked(String reason) {
        int n = 0;
        for (ScanTask t : new ArrayList<>(INSTANCE.tasks)) {
            try { t.delete(); } catch (Throwable ignore) { }
            INSTANCE.tasks.remove(t);
            n++;
        }
        if (n > 0) INSTANCE.note("[verb-guard] " + reason + ": deleted " + n + " Burp crawl/audit task(s) started by AI Scanner.");
        synchronized (INSTANCE) { INSTANCE.maybeDeregisterLocked(); }
        return n;
    }

    /** Extension unload: delete our tasks first (nothing fences them afterwards), then deregister unconditionally. */
    public static void shutdown() {
        deleteTracked("extension unload");
        synchronized (INSTANCE) {
            INSTANCE.windows = 0;
            if (INSTANCE.reg != null) {
                try { INSTANCE.reg.deregister(); } catch (Throwable ignore) { }
                INSTANCE.reg = null;
            }
        }
    }

    private void ensureRegisteredLocked() {
        if (reg != null || api == null) return;
        try { reg = api.http().registerHttpHandler(this); } catch (Throwable ignore) { }
    }

    private void maybeDeregisterLocked() {
        if (reg == null || windows > 0 || !tasks.isEmpty()) return;
        try { reg.deregister(); } catch (Throwable ignore) { }
        reg = null;
    }

    private void note(String line) {
        ScanLog l = log;
        if (l != null) try { l.log(line); } catch (Throwable ignore) { }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) {
        boolean fromScanner;
        try { fromScanner = r.toolSource().isFromTool(ToolType.SCANNER); }
        catch (Throwable t) { return RequestToBeSentAction.continueWith(r); }   // unattributable: not ours to judge
        if (!fromScanner) return RequestToBeSentAction.continueWith(r);
        boolean refuse;
        try { refuse = WriteGuard.blocksDestructiveVerb(r); }
        catch (Throwable t) { refuse = true; }                                  // scanner traffic: fail closed
        if (!refuse) return RequestToBeSentAction.continueWith(r);
        try { SafeHttp.noteBlocked(r, "Burp crawl/audit"); } catch (Throwable ignore) { }
        return refuse(r);
    }

    private static RequestToBeSentAction refuse(HttpRequestToBeSent r) {
        String body = "DELETE/PATCH/MERGE refused by the AI Scanner verb guard (request not sent).";
        try {
            HttpResponse resp = HttpResponse.httpResponse("HTTP/1.1 405 Method Not Allowed\r\n"
                    + "Content-Type: text/plain\r\nX-AI-Scanner-Verb-Guard: refused\r\nContent-Length: "
                    + body.length() + "\r\n\r\n" + body);
            Method spoof = RequestToBeSentAction.class.getMethod("spoof", HttpResponse.class);
            return (RequestToBeSentAction) spoof.invoke(null, resp);
        } catch (Throwable noSpoof) { /* older Burp */ }
        try {
            Method drop = RequestToBeSentAction.class.getMethod("drop");
            return (RequestToBeSentAction) drop.invoke(null);
        } catch (Throwable noDrop) { /* older Burp */ }
        try {
            return RequestToBeSentAction.continueWith(r.withMethod("OPTIONS").withBody("")
                    .withRemovedHeader("X-HTTP-Method-Override").withRemovedHeader("X-HTTP-Method")
                    .withRemovedHeader("X-Method-Override").withPath(r.pathWithoutQuery()));
        } catch (Throwable t) {
            return RequestToBeSentAction.continueWith(r.withMethod("OPTIONS").withBody(""));
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
        return ResponseReceivedAction.continueWith(r);
    }
}
