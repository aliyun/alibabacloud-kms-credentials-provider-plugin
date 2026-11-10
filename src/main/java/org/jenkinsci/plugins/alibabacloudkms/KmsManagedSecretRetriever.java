package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import hudson.util.Secret;
import java.time.Duration;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;

/**
 * Supplies the username/password pair of a managed KMS secret, whose value is a JSON object rather
 * than a bare string.
 *
 * <p>Both halves always come from the same payload and are served from one entry for the configured
 * cache lifetime. Pairing them matters more than freshness: a rotating secret can replace the account
 * name as well as the password, and half of an old pair combined with half of a new one authenticates as
 * nothing at all. A lifetime of {@code 0} disables caching of the pair, so every read goes to KMS live —
 * but the two halves of a single read still come from the one payload.</p>
 *
 * <p>Caching is also what keeps credential dropdowns usable, since Jenkins resolves
 * {@code getUsername()} while rendering every entry.</p>
 */
public class KmsManagedSecretRetriever implements Supplier<Secret> {

    private static final Logger LOG = Logger.getLogger(KmsManagedSecretRetriever.class.getName());

    /**
     * How long a failed read is remembered before it is retried — long enough that an outage costs one
     * timeout per secret rather than one per dropdown entry, short enough that a recovery is not held
     * off for the whole success lifetime. This is a circuit breaker, not a value cache, so it stays in
     * force even when the configured cache lifetime is {@code 0}.
     */
    private static final long FAILURE_TTL_MILLIS = Duration.ofSeconds(30).toMillis();

    private final transient Client client;
    private final String secretName;
    private final String versionId;
    private final ManagedSecretType secretType;
    private final long successTtlMillis;

    private volatile Entry cached;

    public KmsManagedSecretRetriever(
            Client client, String secretName, ManagedSecretType secretType, long cacheSeconds) {
        this(client, secretName, null, secretType, cacheSeconds);
    }

    public KmsManagedSecretRetriever(
            Client client, String secretName, String versionId, ManagedSecretType secretType, long cacheSeconds) {
        this.client = client;
        this.secretName = secretName;
        this.versionId = versionId;
        this.secretType = secretType;
        this.successTtlMillis = cacheSeconds <= 0 ? 0L : cacheSeconds * 1_000L;
    }

    /**
     * The account name / password pair of a managed secret payload. {@code username} is never null but
     * may be empty.
     */
    static final class Value {
        private final String username;
        private final String password;

        Value(String username, String password) {
            this.username = username;
            this.password = password;
        }

        String username() {
            return username;
        }

        String password() {
            return password;
        }
    }

    /**
     * The memoized outcome of the last read — the pair, or the reason it could not be obtained — plus
     * when to stop trusting it. Exactly one of {@code value} and {@code failure} is set.
     */
    private static final class Entry {
        private final Value value;
        private final RuntimeException failure;
        private final long expiresAt;

        Entry(Value value, RuntimeException failure, long expiresAt) {
            this.value = value;
            this.failure = failure;
            this.expiresAt = expiresAt;
        }

        Value get() {
            if (failure != null) {
                throw failure;
            }
            return value;
        }

        boolean isCurrent(long now) {
            return now < expiresAt;
        }
    }

    /**
     * A missing password fails loudly: a credential without one is unusable, and silently substituting
     * an empty password would authenticate as the wrong thing. A missing account name is only a
     * warning, because some managed payloads legitimately carry no account and rejecting those would
     * hide an otherwise usable password.
     */
    static Value parse(String secretName, String data, ManagedSecretType secretType) {
        if (StringUtils.isBlank(data)) {
            throw new KmsPluginException("Secret '" + secretName + "' returned no data");
        }
        try {
            JSONObject json = JSONObject.fromObject(data);
            if (json.isNullObject()) {
                throw new KmsPluginException(
                        "Secret '" + secretName + "' of type " + secretType + " is not a JSON object");
            }

            // GetSecretValue returns every managed type as a flat object: RDS has its internal
            // Version field stripped server-side, and Redis/PolarDB/ECS/RAM are stored flat. The
            // {"Accounts":[...]} shape is only the CreateSecret input, never the retrieved value.
            String passwordKey = secretType.passwordKey();
            if (!json.has(passwordKey)) {
                throw new KmsPluginException(
                        "Secret '" + secretName + "' of type " + secretType + " has no '" + passwordKey + "' field");
            }

            String usernameKey = secretType.usernameKey();
            String username = json.has(usernameKey) ? json.getString(usernameKey) : null;
            if (StringUtils.isEmpty(username)) {
                LOG.log(
                        Level.WARNING,
                        "KMS secret ''{0}'' of type {1} carries no ''{2}''; the username will be empty",
                        new Object[] {secretName, secretType, usernameKey});
                username = "";
            }
            return new Value(username, json.getString(passwordKey));
        } catch (JSONException e) {
            throw new KmsPluginException(
                    "Secret '" + secretName + "' of type " + secretType + " does not hold the expected JSON fields: "
                            + e.getMessage(),
                    e);
        }
    }

    public String getUsername() {
        return value().username();
    }

    @Override
    public Secret get() {
        return Secret.fromString(value().password());
    }

    private Value value() {
        Entry entry = current(now());
        if (entry != null) {
            return entry.get();
        }
        synchronized (this) {
            entry = current(now());
            if (entry != null) {
                return entry.get();
            }
            Entry fresh;
            try {
                fresh = new Entry(parse(secretName, retrieveSecret(), secretType), null, now() + successTtlMillis);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Failed to read managed KMS secret ''{0}'': {1}", new Object[] {
                    secretName, e.getMessage()
                });
                fresh = new Entry(null, e, now() + FAILURE_TTL_MILLIS);
            }
            cached = fresh;
            return fresh.get();
        }
    }

    /** The memoized outcome, or null when there is none or it has expired. */
    private Entry current(long now) {
        Entry entry = cached;
        return entry != null && entry.isCurrent(now) ? entry : null;
    }

    /** Package-private so a test can move the clock instead of sleeping out a lifetime. */
    long now() {
        return System.currentTimeMillis();
    }

    String retrieveSecret() {
        return KmsSecretRetriever.fetchSecretValue(client, secretName, versionId)
                .getSecretData();
    }
}
