package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.util.FormValidation;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

/**
 * Global configuration for the Alibaba Cloud KMS credentials plugin.
 *
 * <p>Every value can be supplied through the UI, an environment variable, or a JVM system property.
 * Environment variables / system properties take precedence so that the endpoint and tag selector
 * can be injected at startup without persisting them to disk. No AccessKey is ever read here:
 * authentication is delegated to {@link KmsClientFactory}.</p>
 */
@Extension
@Symbol("alibabaCloudKms")
public class KmsGlobalConfiguration extends GlobalConfiguration {

    private static final Logger LOG = Logger.getLogger(KmsGlobalConfiguration.class.getName());

    static final String DEFAULT_TAG_KEY = "jenkins:credentials";
    static final String DEFAULT_STEP_ENDPOINT_WHITELIST = "*.aliyuncs.com";
    static final long DEFAULT_CACHE_SECONDS = 300L;
    private static final long MAX_CACHE_SECONDS = Long.MAX_VALUE / 1_000_000_000L;

    private String endpoint;
    private String stepEndpointWhitelist;
    private String tagKey;
    private Long cacheSeconds;

    public KmsGlobalConfiguration() {
        load();
    }

    public String getEndpoint() {
        return resolve("ALIBABA_CLOUD_KMS_ENDPOINT", "jenkins.alibabacloud-kms.endpoint", endpoint, null);
    }

    @DataBoundSetter
    public void setEndpoint(String endpoint) {
        this.endpoint = StringUtils.trimToNull(endpoint);
        save();
        refresh();
    }

    /**
     * Comma-separated host patterns that the {@code endpoint} argument of {@code withAlibabaCloudKms} has
     * to match; {@code *} stands for any run of characters, dots included, and matching is
     * case-insensitive.
     *
     * <p>Needed because naming an endpoint is the one part of a KMS call a pipeline author controls with
     * Job/Configure alone, far below Overall/Administer. Left unbounded, that turns the controller into an
     * outbound probe signed with its own Alibaba Cloud identity. The globally configured endpoint is
     * deliberately not covered by it: setting that already takes Overall/Administer.</p>
     */
    public String getStepEndpointWhitelist() {
        return resolve(
                "ALIBABA_CLOUD_KMS_STEP_ENDPOINT_WHITELIST",
                "jenkins.alibabacloud-kms.stepEndpointWhitelist",
                stepEndpointWhitelist,
                DEFAULT_STEP_ENDPOINT_WHITELIST);
    }

    @DataBoundSetter
    public void setStepEndpointWhitelist(String stepEndpointWhitelist) {
        this.stepEndpointWhitelist = StringUtils.trimToNull(stepEndpointWhitelist);
        save();
    }

    /**
     * Tag selector that marks a KMS secret as managed by Jenkins. KMS matches it as a case-sensitive
     * substring of each secret's tag keys, not as an exact key, so only secrets with at least one tag
     * key containing this text are listed and mapped to credentials.
     */
    public String getTagKey() {
        return resolve("ALIBABA_CLOUD_KMS_TAG_KEY", "jenkins.alibabacloud-kms.tagKey", tagKey, DEFAULT_TAG_KEY);
    }

    @DataBoundSetter
    public void setTagKey(String tagKey) {
        this.tagKey = StringUtils.trimToNull(tagKey);
        save();
        refresh();
    }

    /**
     * How long, in seconds, a retrieved secret value is cached before the next read goes back to KMS.
     * This applies to every credential type, including managed username/password pairs. {@code 0}
     * disables value caching so every read is live. A rotated secret is picked up sooner regardless of
     * this value, because the credential object is keyed on the secret's {@code updateTime}. Credential
     * discovery uses a separate fixed 30-second cache that this setting does not change.
     */
    public long getCacheSeconds() {
        Long environmentValue = parseCacheSeconds(
                "environment variable ALIBABA_CLOUD_KMS_CACHE_SECONDS",
                System.getenv("ALIBABA_CLOUD_KMS_CACHE_SECONDS"));
        if (environmentValue != null) {
            return environmentValue;
        }
        Long systemPropertyValue = parseCacheSeconds(
                "system property jenkins.alibabacloud-kms.cacheSeconds",
                System.getProperty("jenkins.alibabacloud-kms.cacheSeconds"));
        if (systemPropertyValue != null) {
            return systemPropertyValue;
        }
        if (cacheSeconds != null) {
            try {
                return validateCacheSeconds(cacheSeconds);
            } catch (IllegalArgumentException e) {
                LOG.log(Level.WARNING, "Ignoring invalid persisted cacheSeconds: {0}", cacheSeconds);
            }
        }
        return DEFAULT_CACHE_SECONDS;
    }

    @DataBoundSetter
    public void setCacheSeconds(Long cacheSeconds) {
        this.cacheSeconds = validateCacheSeconds(cacheSeconds);
        save();
        reconfigureCache();
    }

    private void refresh() {
        KmsCredentialsProvider provider = provider();
        if (provider != null) {
            provider.refreshCredentials();
        }
    }

    private void reconfigureCache() {
        KmsCredentialsProvider provider = provider();
        if (provider != null) {
            provider.reconfigureCache();
        }
    }

    private static KmsCredentialsProvider provider() {
        return ExtensionList.lookup(KmsCredentialsProvider.class).stream()
                .findFirst()
                .orElse(null);
    }

    static long validateCacheSeconds(Long value) {
        if (value == null || value < 0 || value > MAX_CACHE_SECONDS) {
            throw new IllegalArgumentException(
                    "Cache time must be between 0 (never cache) and " + MAX_CACHE_SECONDS + " seconds");
        }
        return value;
    }

    private static Long parseCacheSeconds(String source, String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }
        try {
            return validateCacheSeconds(Long.parseLong(value.trim()));
        } catch (IllegalArgumentException e) {
            LOG.log(Level.WARNING, "Ignoring invalid {0}: {1}", new Object[] {source, value});
            return null;
        }
    }

    private static String resolve(String envVar, String sysProp, String stored, String fallback) {
        Optional<String> override = envOrSysprop(envVar, sysProp);
        if (override.isPresent()) {
            return override.get();
        }
        return StringUtils.isNotBlank(stored) ? stored : fallback;
    }

    private static Optional<String> envOrSysprop(String envVar, String sysProp) {
        String value = System.getenv(envVar);
        if (StringUtils.isNotBlank(value)) {
            return Optional.of(value.trim());
        }
        value = System.getProperty(sysProp);
        if (StringUtils.isNotBlank(value)) {
            return Optional.of(value.trim());
        }
        return Optional.empty();
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    @POST
    public FormValidation doCheckCacheSeconds(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (StringUtils.isBlank(value)) {
            return FormValidation.error("Cache time is required and must be expressed in seconds");
        }
        try {
            validateCacheSeconds(Long.parseLong(value.trim()));
            return FormValidation.ok();
        } catch (IllegalArgumentException e) {
            return FormValidation.error(e.getMessage());
        }
    }

    @POST
    public FormValidation doReloadCache() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        refresh();
        return FormValidation.ok("Credential and discovery caches reloaded");
    }

    @POST
    @SuppressWarnings("unused")
    public FormValidation doTestConnection(
            @QueryParameter("endpoint") final String endpoint,
            @QueryParameter("tagKey") final String tagKey) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        if (StringUtils.isBlank(endpoint)) {
            return FormValidation.error("Endpoint is required");
        }

        String effectiveTagKey = StringUtils.defaultIfBlank(tagKey, DEFAULT_TAG_KEY);
        try {
            Client client = KmsClientFactory.createClient(endpoint);
            com.aliyun.kms20160120.models.ListSecretsRequest request =
                    new com.aliyun.kms20160120.models.ListSecretsRequest()
                            .setFilters(KmsCredentialsProvider.buildTagFilter(effectiveTagKey))
                            .setPageNumber(1)
                            .setPageSize(1);
            com.aliyun.kms20160120.models.ListSecretsResponse response = client.listSecrets(request);
            Integer total = response != null && response.getBody() != null
                    ? response.getBody().getTotalCount()
                    : null;
            int found = total == null ? 0 : total;
            if (found == 0) {
                return FormValidation.ok(
                        "Success, but found 0 secret(s) selected by '%s'. KMS matches the tag key as a"
                                + " case-sensitive substring, so a secret is only discovered when one of its tag keys contains"
                                + " that text - for example '%s:type'.",
                        effectiveTagKey, effectiveTagKey);
            }
            return FormValidation.ok("Success. Found %d secret(s) tagged with '%s'.", found, effectiveTagKey);
        } catch (Exception | LinkageError e) {
            LOG.log(Level.WARNING, "Failed testing Alibaba Cloud KMS connection", e);
            return FormValidation.error(e, "Failed to connect: " + e.getMessage());
        }
    }

    public static KmsGlobalConfiguration get() {
        return ExtensionList.lookupSingleton(KmsGlobalConfiguration.class);
    }
}
