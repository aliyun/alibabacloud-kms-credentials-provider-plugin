package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GetSecretValueRequest;
import com.aliyun.kms20160120.models.GetSecretValueResponse;
import com.aliyun.kms20160120.models.GetSecretValueResponseBody;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;

/**
 * Lazily retrieves a secret value from Alibaba Cloud KMS Secrets Manager on demand.
 *
 * <p>{@link #get()} memoizes the value for the configured cache lifetime so that repeated reads of an
 * unchanged secret — a page render, a dropdown, several bindings in one build — cost one KMS call rather
 * than one per read. A lifetime of {@code 0} disables that memoization and every read goes to KMS live.
 * A rotated secret is still picked up promptly regardless of the lifetime: the credential object that
 * owns this retriever is keyed on the secret's {@code updateTime}, so a rotation builds a fresh
 * retriever rather than reusing a stale value.</p>
 *
 * <p>{@link #retrieveSecret()} is always a live read with no memoization, for callers such as the
 * configuration-as-code secret source that must resolve the current value at startup.</p>
 */
public class KmsSecretRetriever implements Supplier<Secret> {

    private final transient Client client;
    private final String secretName;
    private final String versionId;
    private final long cacheMillis;

    private volatile Entry cached;

    /** A no-cache retriever: every {@link #get()} reads live. */
    public KmsSecretRetriever(Client client, String secretName) {
        this(client, secretName, null, 0L);
    }

    public KmsSecretRetriever(Client client, String secretName, String versionId, long cacheSeconds) {
        this.client = client;
        this.secretName = secretName;
        this.versionId = versionId;
        this.cacheMillis = cacheSeconds <= 0 ? 0L : cacheSeconds * 1_000L;
    }

    private static final class Entry {
        private final Secret value;
        private final long expiresAt;

        Entry(Secret value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }

        Secret value() {
            return value;
        }

        long expiresAt() {
            return expiresAt;
        }
    }

    /**
     * The one place that issues a {@code GetSecretValue} call, shared by both retrievers and by
     * {@link KmsStep}. Returns the whole response body rather than the payload because {@link KmsStep}
     * also needs {@code SecretDataType} to tell a binary secret from a text one.
     */
    static GetSecretValueResponseBody fetchSecretValue(Client client, String secretName, String versionId) {
        try {
            GetSecretValueRequest request = new GetSecretValueRequest().setSecretName(secretName);
            if (StringUtils.isNotBlank(versionId)) {
                request.setVersionId(versionId);
            }
            GetSecretValueResponse response = client.getSecretValue(request);
            if (response == null || response.getBody() == null) {
                throw new KmsPluginException("Empty response retrieving secret: " + secretName);
            }
            return response.getBody();
        } catch (KmsPluginException e) {
            throw e;
        } catch (Exception e) {
            throw new KmsPluginException(
                    "Failed to retrieve secret '" + secretName + "' from Alibaba Cloud KMS: " + e.getMessage(), e);
        }
    }

    public String retrieveSecret() {
        String data = fetchSecretValue(client, secretName, versionId).getSecretData();
        if (data == null) {
            // Must fail here rather than hand back null: Secret.fromString(null) silently becomes
            // an empty value, so a credential would bind an empty password instead of erroring.
            throw new KmsPluginException("Secret '" + secretName + "' returned no data");
        }
        return data;
    }

    @Override
    public Secret get() {
        if (cacheMillis <= 0) {
            return Secret.fromString(retrieveSecret());
        }
        Entry entry = current(now());
        if (entry != null) {
            return entry.value();
        }
        synchronized (this) {
            entry = current(now());
            if (entry != null) {
                return entry.value();
            }
            // A failure is not memoized: it propagates and the next read retries live, matching the
            // pre-caching behaviour for ordinary secrets.
            Secret fresh = Secret.fromString(retrieveSecret());
            cached = new Entry(fresh, now() + cacheMillis);
            return fresh;
        }
    }

    private Entry current(long now) {
        Entry entry = cached;
        return entry != null && now < entry.expiresAt() ? entry : null;
    }

    /** Package-private so a test can move the clock instead of sleeping out a lifetime. */
    long now() {
        return System.currentTimeMillis();
    }
}
