package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.ListSecretsRequest;
import com.aliyun.kms20160120.models.ListSecretsResponse;
import com.aliyun.kms20160120.models.ListSecretsResponseBody;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecret;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecretTagsTag;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Ticker;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import hudson.util.Secret;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.alibabacloudkms.credentials.certificate.KmsCertificateCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.secretfile.KmsSecretFileCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.sshuserprivatekey.KmsSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.string.KmsStringCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.usernamepassword.KmsUsernamePasswordCredentials;
import org.acegisecurity.Authentication;

/**
 * Exposes Alibaba Cloud KMS Secrets Manager secrets as Jenkins credentials.
 *
 * <p>Secrets are selected server-side by a tag key (default {@code jenkins:credentials}). Each secret's
 * tags drive how it is mapped to a concrete credential type, mirroring the well-known Azure Key Vault
 * plugin conventions. Ordinary secret values are fetched lazily on first use; managed
 * username/password retrievers retain their pair together.</p>
 */
@Extension
public class KmsCredentialsProvider extends CredentialsProvider {

    private static final Logger LOG = Logger.getLogger(KmsCredentialsProvider.class.getName());

    private static final String DEFAULT_TYPE = "string";
    private static final String DEFAULT_SCOPE = "GLOBAL";

    /** No KMS tag maps onto a Jenkins credential description, so every projected credential gets an empty one. */
    private static final String NO_DESCRIPTION = "";

    private static final String TAG_ID = "jenkins:credentials:id";
    private static final String TAG_TYPE = "jenkins:credentials:type";
    private static final String TAG_SCOPE = "jenkins:credentials:scope";

    private static final String TAG_USERNAME = "jenkins:credentials:username";
    private static final String TAG_FILE_NAME = "jenkins:credentials:filename";
    private static final String TAG_PASSPHRASE_ID = "jenkins:credentials:passphrase-id";
    private static final String TAG_PASSWORD_ID = "jenkins:credentials:password-id";
    private static final String TAG_AUTO_PARSE_SECRET = "jenkins:credentials:auto-parse-secret";

    private static final int PAGE_SIZE = 100;
    private static final int MAX_PAGES = 50;
    private static final long MAX_CACHED_CREDENTIALS = (long) PAGE_SIZE * MAX_PAGES;

    /**
     * How long a discovery result is served as-is before the next lookup triggers a reload. The reload
     * runs in the background and the caller still gets the previous result, so no credential lookup ever
     * waits on KMS except the very first one for a given configuration.
     */
    private static final long CREDENTIAL_LIST_REFRESH_SECONDS = 30L;

    /**
     * Hard bound on staleness for a controller that stops looking credentials up altogether: past it the
     * entry is dropped and the next lookup blocks on a fresh load. On a busy controller the refresh above
     * always wins, so this only ever decides how long an idle one may serve old membership.
     */
    private static final long CREDENTIAL_LIST_EXPIRE_SECONDS = 300L;

    /**
     * Runs the discovery cache's background refresh. A single shared daemon thread rather than
     * {@link java.util.concurrent.ForkJoinPool#commonPool()}: a reload is blocking network IO against
     * KMS — up to {@link #MAX_PAGES} calls, each with its own read timeout — and parking a common-pool
     * thread on it would starve every other common-pool user on the controller for the duration. The
     * core thread times out when idle, so a controller that never looks credentials up holds no thread.
     */
    private static final Executor REFRESH_EXECUTOR = newRefreshExecutor();

    private static Executor newRefreshExecutor() {
        ThreadPoolExecutor executor =
                new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), runnable -> {
                    Thread thread = new Thread(runnable, "kms-credential-discovery-refresh");
                    thread.setDaemon(true);
                    return thread;
                });
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    private final KmsCredentialsStore store = new KmsCredentialsStore(this);
    private volatile CacheState cacheState = newCacheState(KmsGlobalConfiguration.DEFAULT_CACHE_SECONDS);

    /**
     * Overrides the camel-case split of the class name, which would render as
     * "Kms Credentials Provider" in store and provider tooltips across the credentials UI.
     */
    @NonNull
    @Override
    public String getDisplayName() {
        return "Alibaba Cloud Kms Credentials Provider";
    }

    private static final class CacheState {
        private final long cacheSeconds;
        private final LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> credentialListCache;

        CacheState(
                long cacheSeconds,
                LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> credentialListCache) {
            this.cacheSeconds = cacheSeconds;
            this.credentialListCache = credentialListCache;
        }

        long cacheSeconds() {
            return cacheSeconds;
        }

        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> credentialListCache() {
            return credentialListCache;
        }
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(
            @NonNull Class<C> type,
            @Nullable ItemGroup itemGroup,
            @Nullable Authentication authentication,
            @NonNull List<DomainRequirement> domainRequirements) {
        if (ACL.SYSTEM.equals(authentication)) {
            final ArrayList<C> list = new ArrayList<>();
            try {
                Map<String, IdCredentials> credentials = fetchCredentials();

                for (IdCredentials credential : credentials.values()) {
                    if (type.isAssignableFrom(credential.getClass())) {
                        if (CredentialsScope.SYSTEM == credential.getScope() && !(itemGroup instanceof Jenkins)) {
                            LOG.log(
                                    Level.FINEST,
                                    "getCredentials {0} has SYSTEM scope but the context is not Jenkins. Ignoring credential",
                                    credential.getId());
                        } else {
                            list.add(type.cast(credential));
                        }
                    }
                }
            } catch (RuntimeException | LinkageError e) {
                LOG.log(Level.WARNING, "Error retrieving secrets from Alibaba Cloud KMS: " + e.getMessage(), e);
                return Collections.emptyList();
            }
            return list;
        }
        return Collections.emptyList();
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(
            @NonNull Class<C> type, @Nullable ItemGroup itemGroup, @Nullable Authentication authentication) {
        return getCredentials(type, itemGroup, authentication, Collections.emptyList());
    }

    /**
     * The {@code Item} overloads are deliberately not overridden: the base class resolves an item to
     * {@code item instanceof ItemGroup ? (ItemGroup) item : item.getParent()}, which is what lets a
     * SYSTEM-scoped credential stay visible to a top-level job. Delegating with a {@code null} item group
     * instead would satisfy {@code !(itemGroup instanceof Jenkins)} and hide every one of them.
     */
    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.get() ? store : null;
    }

    public void refreshCredentials() {
        synchronized (this) {
            cacheState = newCacheState(cacheState.cacheSeconds());
        }
    }

    void reconfigureCache() {
        KmsGlobalConfiguration configuration = GlobalConfiguration.all().get(KmsGlobalConfiguration.class);
        reconfigureCache(
                configuration == null ? KmsGlobalConfiguration.DEFAULT_CACHE_SECONDS : configuration.getCacheSeconds());
    }

    void reconfigureCache(long cacheSeconds) {
        synchronized (this) {
            cacheState = newCacheState(cacheSeconds);
        }
    }

    /**
     * Builds both caches as a pair. The discovery cache's loader captures the credential cache it fills,
     * so a new credential cache has to come with a new discovery cache rather than being paired with the
     * previous one.
     */
    private static CacheState newCacheState(long cacheSeconds) {
        long validatedCacheSeconds = KmsGlobalConfiguration.validateCacheSeconds(cacheSeconds);
        Cache<SecretCacheKey, IdCredentials> credentialCache = newCache(validatedCacheSeconds);
        return new CacheState(validatedCacheSeconds, newCredentialListCache(credentialCache, validatedCacheSeconds));
    }

    static <K, V> Cache<K, V> newCache(long cacheSeconds) {
        return Caffeine.<K, V>newBuilder()
                .maximumSize(MAX_CACHED_CREDENTIALS)
                .expireAfterWrite(Duration.ofSeconds(KmsGlobalConfiguration.validateCacheSeconds(cacheSeconds)))
                .build();
    }

    static LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> newCredentialListCache(
            Cache<SecretCacheKey, IdCredentials> credentialCache, long cacheSeconds) {
        return newCredentialListCache(
                listLoader(credentialCache, cacheSeconds), Ticker.systemTicker(), REFRESH_EXECUTOR);
    }

    /** Test seam: a supplied ticker and executor make the refresh window and the reload itself deterministic. */
    static LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> newCredentialListCache(
            CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>> loader, Ticker ticker, Executor executor) {
        return Caffeine.<CredentialListCacheKey, Map<String, IdCredentials>>newBuilder()
                .maximumSize(1)
                .refreshAfterWrite(Duration.ofSeconds(CREDENTIAL_LIST_REFRESH_SECONDS))
                .expireAfterWrite(Duration.ofSeconds(CREDENTIAL_LIST_EXPIRE_SECONDS))
                .ticker(ticker)
                .executor(executor)
                .build(loader);
    }

    /**
     * Wires Caffeine's two entry points onto {@link #loadCredentialList}: a first load has nothing to
     * fall back to, a refresh falls back to the list it is replacing.
     *
     * <p>Handing a value back from {@code reload} instead of letting the failure propagate also re-arms
     * the refresh clock. A propagated failure leaves the old entry in place with its old write time, so
     * every subsequent lookup — a page render, a dropdown, a binding — would queue another reload on
     * {@link #REFRESH_EXECUTOR}, one per call for the whole outage. Storing a value again makes it one per
     * discovery window.</p>
     */
    private static CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>> listLoader(
            Cache<SecretCacheKey, IdCredentials> credentialCache, long cacheSeconds) {
        return new CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>>() {
            @Override
            public Map<String, IdCredentials> load(CredentialListCacheKey key) {
                return loadCredentialList(key, Collections.emptyMap(), credentialCache, cacheSeconds);
            }

            @Override
            public Map<String, IdCredentials> reload(
                    CredentialListCacheKey key, Map<String, IdCredentials> currentValue) {
                return loadCredentialList(key, currentValue, credentialCache, cacheSeconds);
            }
        };
    }

    private CacheState cacheState(KmsGlobalConfiguration configuration) {
        long configuredCacheSeconds = configuration.getCacheSeconds();
        CacheState current = cacheState;
        if (current.cacheSeconds() == configuredCacheSeconds) {
            return current;
        }
        synchronized (this) {
            current = cacheState;
            if (current.cacheSeconds() != configuredCacheSeconds) {
                current = newCacheState(configuredCacheSeconds);
                cacheState = current;
            }
            return current;
        }
    }

    private Map<String, IdCredentials> fetchCredentials() {
        KmsGlobalConfiguration config = GlobalConfiguration.all().get(KmsGlobalConfiguration.class);
        if (config == null) {
            return Collections.emptyMap();
        }
        String endpoint = config.getEndpoint();
        if (StringUtils.isBlank(endpoint)) {
            LOG.log(Level.FINE, "Alibaba Cloud KMS endpoint is not configured; skipping credential retrieval");
            return Collections.emptyMap();
        }

        String tagKey = config.getTagKey();
        CacheState current = cacheState(config);
        Map<String, IdCredentials> credentials =
                current.credentialListCache().get(CredentialListCacheKey.of(endpoint, tagKey));
        return credentials == null ? Collections.emptyMap() : credentials;
    }

    /**
     * Loads the credential list, converting a failure into {@code fallback} so that Caffeine caches it
     * for the discovery window: an empty map on the first load, the list that was already there on a
     * refresh.
     *
     * <p>Serving the previous list rather than an empty one is deliberate. Withdrawing every credential
     * from every picker would break every {@code withCredentials} for as long as KMS is unreachable,
     * which is worse than serving slightly stale membership — secret <em>values</em> are still read live,
     * so a secret deleted during the outage fails at the point of use instead of silently vanishing.</p>
     *
     * <p>Caching the failure matters as much as caching the success: this cache holds a single entry, so
     * while a load is in flight every other caller for it queues behind it. Credential lookups are among
     * the highest-frequency calls Jenkins makes — rendering a page, filling a dropdown, each
     * {@code withCredentials} — so letting every one of them pay a full KMS timeout during an outage
     * would exhaust the request thread pool and take the controller down with it. An empty result is
     * therefore the sentinel for both "no matching secrets" and "KMS is unreachable"; the distinction is
     * logged rather than cached.</p>
     *
     * <p>{@link LinkageError} is caught alongside {@link Exception} because a broken dependency plugin
     * surfaces as {@link NoClassDefFoundError}, which is an {@code Error} and would otherwise escape
     * through {@link CredentialsProvider#lookupCredentials} and fail every credential-consuming page on
     * the controller, not just KMS.</p>
     */
    static Map<String, IdCredentials> loadCredentialList(
            CredentialListCacheKey key,
            Map<String, IdCredentials> fallback,
            Cache<SecretCacheKey, IdCredentials> credentialCache,
            long cacheSeconds) {
        try {
            return fetchCredentials(
                    key.endpoint(),
                    key.tagKey(),
                    KmsClientFactory.createClient(key.endpoint()),
                    credentialCache,
                    cacheSeconds);
        } catch (Exception | LinkageError e) {
            LOG.log(Level.WARNING, "Error retrieving secrets from Alibaba Cloud KMS: " + e.getMessage(), e);
            return fallback;
        }
    }

    static Map<String, IdCredentials> fetchCredentials(
            String endpoint,
            String tagKey,
            Client client,
            Cache<SecretCacheKey, IdCredentials> credentialCache,
            long cacheSeconds)
            throws Exception {
        String filter = buildTagFilter(tagKey);
        Map<String, IdCredentials> credentials = new HashMap<>();
        for (int pageNumber = 1; pageNumber <= MAX_PAGES; pageNumber++) {
            ListSecretsRequest request = new ListSecretsRequest()
                    .setFilters(filter)
                    .setFetchTags("true")
                    .setPageNumber(pageNumber)
                    .setPageSize(PAGE_SIZE);
            ListSecretsResponse response = client.listSecrets(request);
            if (response == null || response.getBody() == null) {
                break;
            }
            ListSecretsResponseBody body = response.getBody();
            if (body.getSecretList() == null
                    || body.getSecretList().getSecret() == null
                    || body.getSecretList().getSecret().isEmpty()) {
                break;
            }
            for (ListSecretsResponseBodySecretListSecret secret :
                    body.getSecretList().getSecret()) {
                IdCredentials credential =
                        mapSecretToCredentials(secret, client, endpoint, credentialCache, cacheSeconds);
                if (credential == null) {
                    continue;
                }
                IdCredentials existing = credentials.putIfAbsent(credential.getId(), credential);
                if (existing != null) {
                    LOG.log(
                            Level.WARNING,
                            "Skipping KMS secret ''{0}'': its Jenkins credential id ''{1}'' is already taken by another secret",
                            new Object[] {secret.getSecretName(), credential.getId()});
                }
            }
            Integer totalCount = body.getTotalCount();
            if (totalCount == null || (long) pageNumber * PAGE_SIZE >= totalCount) {
                break;
            }
            if (pageNumber == MAX_PAGES) {
                LOG.log(
                        Level.WARNING,
                        "Alibaba Cloud KMS credential discovery stopped at the {0}-page cap: {1} secret(s) match tag key ''{2}'' but only the first {3} were mapped",
                        new Object[] {MAX_PAGES, totalCount, tagKey, (long) MAX_PAGES * PAGE_SIZE});
                break;
            }
        }
        LOG.log(Level.INFO, "Loaded {0} credential(s) from Alibaba Cloud KMS (tag key ''{1}'')", new Object[] {
            credentials.size(), tagKey
        });
        return Collections.unmodifiableMap(new HashMap<>(credentials));
    }

    private static IdCredentials mapSecretToCredentials(
            ListSecretsResponseBodySecretListSecret secret,
            Client client,
            String endpoint,
            Cache<SecretCacheKey, IdCredentials> credentialCache,
            long cacheSeconds) {
        String secretName = secret.getSecretName();
        if (StringUtils.isBlank(secretName)) {
            return null;
        }
        if (StringUtils.isNotBlank(secret.getPlannedDeleteTime())) {
            LOG.log(Level.FINE, "Skipping secret ''{0}'': it is pending deletion", secretName);
            return null;
        }
        try {
            Map<String, String> tags = toTagMap(secret);
            if (StringUtils.isBlank(secret.getUpdateTime())) {
                return createCredential(secret, client, tags, cacheSeconds);
            }
            SecretCacheKey cacheKey = SecretCacheKey.of(endpoint, secret, tags);
            return credentialCache.get(cacheKey, ignored -> createCredential(secret, client, tags, cacheSeconds));
        } catch (Exception e) {
            LOG.log(
                    Level.WARNING,
                    "Error mapping KMS secret '" + secretName + "' to a credential: " + e.getMessage(),
                    e);
            return null;
        }
    }

    private static IdCredentials createCredential(
            ListSecretsResponseBodySecretListSecret secret,
            Client client,
            Map<String, String> tags,
            long cacheSeconds) {
        String secretName = secret.getSecretName();
        String secretType = secret.getSecretType();
        String type = tags.getOrDefault(TAG_TYPE, DEFAULT_TYPE);
        String jenkinsId = StringUtils.defaultIfBlank(tags.get(TAG_ID), secretName);
        String tagScope = tags.getOrDefault(TAG_SCOPE, DEFAULT_SCOPE);
        CredentialsScope scope =
                "SYSTEM".equalsIgnoreCase(tagScope) ? CredentialsScope.SYSTEM : CredentialsScope.GLOBAL;

        switch (type) {
            case "string":
                return new KmsStringCredentials(
                        scope,
                        jenkinsId,
                        NO_DESCRIPTION,
                        new KmsSecretRetriever(client, secretName, null, cacheSeconds));
            case "secretFile":
                String fileName = tags.get(TAG_FILE_NAME);
                if (StringUtils.isBlank(fileName)) {
                    fileName = secretName + ".txt";
                }
                return new KmsSecretFileCredentials(
                        scope,
                        jenkinsId,
                        NO_DESCRIPTION,
                        fileName,
                        new KmsSecretRetriever(client, secretName, null, cacheSeconds));
            case "username":
                Optional<ManagedSecretType> managedType = Boolean.parseBoolean(tags.get(TAG_AUTO_PARSE_SECRET))
                        ? ManagedSecretType.from(secretType)
                        : Optional.empty();
                if (managedType.isPresent()) {
                    KmsManagedSecretRetriever retriever =
                            new KmsManagedSecretRetriever(client, secretName, managedType.get(), cacheSeconds);
                    return new KmsUsernamePasswordCredentials(
                            scope,
                            jenkinsId,
                            usernameSupplier(tags.get(TAG_USERNAME), retriever::getUsername),
                            NO_DESCRIPTION,
                            retriever);
                }
                return new KmsUsernamePasswordCredentials(
                        scope,
                        jenkinsId,
                        usernameSupplier(tags.get(TAG_USERNAME), () -> ""),
                        NO_DESCRIPTION,
                        new KmsSecretRetriever(client, secretName, null, cacheSeconds));
            case "sshUserPrivateKey":
                return new KmsSSHUserPrivateKeyCredentials(
                        scope,
                        jenkinsId,
                        NO_DESCRIPTION,
                        tags.get(TAG_USERNAME),
                        referencedSecret(client, tags.get(TAG_PASSPHRASE_ID), cacheSeconds),
                        new KmsSecretRetriever(client, secretName, null, cacheSeconds));
            case "certificate":
                return new KmsCertificateCredentials(
                        scope,
                        jenkinsId,
                        NO_DESCRIPTION,
                        referencedSecret(client, tags.get(TAG_PASSWORD_ID), cacheSeconds),
                        new KmsSecretRetriever(client, secretName, null, cacheSeconds));
            default:
                LOG.log(
                        Level.WARNING,
                        "Unknown credential type ''{0}'' for KMS secret ''{1}''; skipping",
                        new Object[] {type, secretName});
                return null;
        }
    }

    /**
     * A configured {@code username} tag wins outright, so rendering a credential list costs no KMS
     * calls; only when it is absent does the username come from inside the secret value.
     */
    private static Supplier<String> usernameSupplier(String taggedUsername, Supplier<String> parsed) {
        return StringUtils.isNotBlank(taggedUsername) ? () -> taggedUsername : parsed;
    }

    private static Supplier<Secret> referencedSecret(Client client, String referencedName, long cacheSeconds) {
        if (StringUtils.isBlank(referencedName)) {
            return () -> Secret.fromString("");
        }
        return new KmsSecretRetriever(client, referencedName, null, cacheSeconds);
    }

    static final class CredentialListCacheKey {
        private final String endpoint;
        private final String tagKey;

        CredentialListCacheKey(String endpoint, String tagKey) {
            this.endpoint = endpoint;
            this.tagKey = tagKey;
        }

        static CredentialListCacheKey of(String endpoint, String tagKey) {
            return new CredentialListCacheKey(endpoint, tagKey);
        }

        String endpoint() {
            return endpoint;
        }

        String tagKey() {
            return tagKey;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CredentialListCacheKey)) {
                return false;
            }
            CredentialListCacheKey other = (CredentialListCacheKey) o;
            return Objects.equals(endpoint, other.endpoint) && Objects.equals(tagKey, other.tagKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(endpoint, tagKey);
        }
    }

    static final class SecretCacheKey {
        private final String endpoint;
        private final String secretName;
        private final String secretType;
        private final String updateTime;
        private final String id;
        private final String type;
        private final String scope;
        private final String username;
        private final String fileName;
        private final String passphraseId;
        private final String passwordId;
        private final String autoParseSecret;

        SecretCacheKey(
                String endpoint,
                String secretName,
                String secretType,
                String updateTime,
                String id,
                String type,
                String scope,
                String username,
                String fileName,
                String passphraseId,
                String passwordId,
                String autoParseSecret) {
            this.endpoint = endpoint;
            this.secretName = secretName;
            this.secretType = secretType;
            this.updateTime = updateTime;
            this.id = id;
            this.type = type;
            this.scope = scope;
            this.username = username;
            this.fileName = fileName;
            this.passphraseId = passphraseId;
            this.passwordId = passwordId;
            this.autoParseSecret = autoParseSecret;
        }

        static SecretCacheKey of(
                String endpoint, ListSecretsResponseBodySecretListSecret secret, Map<String, String> tags) {
            return new SecretCacheKey(
                    endpoint,
                    secret.getSecretName(),
                    secret.getSecretType(),
                    secret.getUpdateTime(),
                    tags.get(TAG_ID),
                    tags.get(TAG_TYPE),
                    tags.get(TAG_SCOPE),
                    tags.get(TAG_USERNAME),
                    tags.get(TAG_FILE_NAME),
                    tags.get(TAG_PASSPHRASE_ID),
                    tags.get(TAG_PASSWORD_ID),
                    tags.get(TAG_AUTO_PARSE_SECRET));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof SecretCacheKey)) {
                return false;
            }
            SecretCacheKey other = (SecretCacheKey) o;
            return Objects.equals(endpoint, other.endpoint)
                    && Objects.equals(secretName, other.secretName)
                    && Objects.equals(secretType, other.secretType)
                    && Objects.equals(updateTime, other.updateTime)
                    && Objects.equals(id, other.id)
                    && Objects.equals(type, other.type)
                    && Objects.equals(scope, other.scope)
                    && Objects.equals(username, other.username)
                    && Objects.equals(fileName, other.fileName)
                    && Objects.equals(passphraseId, other.passphraseId)
                    && Objects.equals(passwordId, other.passwordId)
                    && Objects.equals(autoParseSecret, other.autoParseSecret);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    endpoint,
                    secretName,
                    secretType,
                    updateTime,
                    id,
                    type,
                    scope,
                    username,
                    fileName,
                    passphraseId,
                    passwordId,
                    autoParseSecret);
        }
    }

    private static Map<String, String> toTagMap(ListSecretsResponseBodySecretListSecret secret) {
        Map<String, String> tags = new HashMap<>();
        if (secret.getTags() == null || secret.getTags().getTag() == null) {
            return tags;
        }
        for (ListSecretsResponseBodySecretListSecretTagsTag tag :
                secret.getTags().getTag()) {
            if (tag != null && tag.getTagKey() != null) {
                tags.put(tag.getTagKey(), tag.getTagValue());
            }
        }
        return tags;
    }

    /**
     * Builds the server-side {@code Filters} JSON selecting secrets that carry the given tag key.
     */
    static String buildTagFilter(String tagKey) {
        return "[{\"Key\":\"TagKey\",\"Values\":[\"" + escapeJson(tagKey) + "\"]}]";
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
