package com.ioactive.aiscanner.scan;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Per-action risk tiering + a gate for state-changing sends — a lesson borrowed from Burp AT, whose tools
 * carry {@code DESTRUCTIVE / IDEMPOTENT / INERT / READ} annotations and whose "Judge" rates a resolved
 * request's risk BEFORE it is sent.
 *
 * <p>We already keep detection deterministic and zero-FP; this adds the missing safety/precision layer on the
 * WRITE side: don't blind-POST an exercise to an arbitrary endpoint just because a field name matched. A
 * concrete case it fixes — an empty-credentials "registration" was fired at {@code /rest/order-history} and
 * {@code /rest/saveLoginIp} (email-bearing but NOT registration sinks), producing spurious 500s. The gate is
 * generic: it reasons from the request method, the path, and the learned schema — never from app identity.
 */
public final class WriteGuard {

    /** READ = safe/idempotent GET-like; WRITE = state-changing (POST/PATCH); DESTRUCTIVE = PUT/DELETE. */
    public enum Tier { READ, WRITE, DESTRUCTIVE }

    private WriteGuard() { }

    public static Tier tier(String method) {
        if (method == null) return Tier.WRITE;
        switch (method.toUpperCase()) {
            case "GET": case "HEAD": case "OPTIONS": case "TRACE": return Tier.READ;
            case "PUT": case "DELETE": return Tier.DESTRUCTIVE;
            default: return Tier.WRITE;   // POST / PATCH / other
        }
    }

    // A registration sink is a NOUN collection you create an account in (users, accounts, members, register,
    // signup, …) — identified by PATH. Deliberately path-only: a password-like field in the RESPONSE is NOT a
    // registration signal (endpoints like /rest/saveLoginIp echo a password hash yet accept no registration),
    // so keying on schema fields false-fired. Universal web idioms, not app-specific names. Handles plurals.
    private static final Pattern REGISTRATION_PATH = Pattern.compile(
            "(?i).*/(?:users?|regist(?:er|ration)s?|sign-?ups?|accounts?|auth|customers?|members?)(?:/|$|\\?).*");

    /**
     * Gate for an empty-/weak-credentials registration exercise: allow ONLY when the target PATH is a plausible
     * registration/users collection. Rejects arbitrary email/password-bearing endpoints (order history,
     * login-IP logs, …) that are not account-creation sinks. Under-fires by design — a blind write is worse
     * than a missed one.
     */
    public static boolean allowsRegistration(String url, List<String> schemaKeys) {
        return url != null && REGISTRATION_PATH.matcher(Net.stripQuery(url)).matches();
    }

    /** True when a state-changing exercise of this method is allowed to be sent unattended (never DESTRUCTIVE). */
    public static boolean allowsUnattended(String method) {
        return tier(method) != Tier.DESTRUCTIVE;
    }

}
