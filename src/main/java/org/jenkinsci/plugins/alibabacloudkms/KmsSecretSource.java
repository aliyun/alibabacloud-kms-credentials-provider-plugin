package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import com.aliyun.tea.TeaException;
import hudson.Extension;
import io.jenkins.plugins.casc.SecretSource;
import java.io.IOException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import org.apache.commons.lang3.StringUtils;

/**
 * Lets the Configuration as Code plugin interpolate Alibaba Cloud KMS secret values into
 * {@code ${secret-name}} placeholders found anywhere in a JCasC document, resolved when the
 * controller configuration is applied at start-up.
 *
 * <p>The endpoint is inherited from {@link KmsGlobalConfiguration}; when no endpoint is configured
 * this source is inert and every lookup short-circuits, so no KMS call is made and other secret
 * sources still handle the placeholder.</p>
 *
 * <p>Once an endpoint is configured the lookup follows the contract {@link SecretSource#reveal} sets
 * for its callers. The only recoverable outcome is KMS answering that it has no such secret: that is
 * logged and the placeholder is passed on to the remaining sources. Everything else is reported so
 * that the configuration apply fails — the endpoint does not resolve, the connection is refused or
 * times out, or KMS rejects the credential. The alternative to failing is the empty string JCasC
 * substitutes for an unresolved variable, and a controller that comes up with a blanked password is
 * indistinguishable from a healthy one, while one that refuses to start is noticed immediately.
 * {@code ${name:-}} still works for a placeholder that is genuinely meant to be optional.</p>
 *
 * <p>Registered with a negative ordinal so that it is consulted last. The built-in sources all use the
 * default ordinal, and a lookup this source cannot carry out must not preempt a placeholder one of
 * them was about to resolve.</p>
 *
 * <p>Bootstrap caveat: because the global configuration may itself be declared in the same JCasC
 * document that is being resolved, authentication has to come from the Alibaba Cloud default credential
 * chain (for example {@code ALIBABA_CLOUD_ACCESS_KEY_ID} / {@code ALIBABA_CLOUD_ACCESS_KEY_SECRET}),
 * which is already in place at boot.</p>
 */
@Extension(optional = true, ordinal = -100)
public class KmsSecretSource extends SecretSource {

    private static final Logger LOG = Logger.getLogger(KmsSecretSource.class.getName());

    private static final int NOT_FOUND = 404;

    @Override
    public Optional<String> reveal(String secret) throws IOException {
        if (StringUtils.isBlank(secret)) {
            return Optional.empty();
        }

        KmsGlobalConfiguration configuration = GlobalConfiguration.all().get(KmsGlobalConfiguration.class);
        if (configuration == null) {
            return Optional.empty();
        }
        String endpoint = configuration.getEndpoint();
        if (StringUtils.isBlank(endpoint)) {
            LOG.fine("No Alibaba Cloud KMS endpoint configured, skipping JCasC secret resolution");
            return Optional.empty();
        }

        try {
            Client client = KmsClientFactory.createClient(endpoint);
            String value = new KmsSecretRetriever(client, secret).retrieveSecret();
            return Optional.ofNullable(StringUtils.isEmpty(value) ? null : value);
        } catch (RuntimeException e) {
            if (kmsSaidNotFound(e)) {
                // Recoverable: the backing store answered that it has no such secret, which is exactly
                // the case the contract says to hand back to the resolver chain. Logged without the
                // value, so nothing sensitive reaches the log.
                LOG.log(Level.INFO, "Alibaba Cloud KMS has no secret ''{0}'' for JCasC resolution: {1}", new Object[] {
                    secret, e.getMessage()
                });
                return Optional.empty();
            }
            // Unrecoverable: the call never completed, KMS rejected the credential, or no client could be
            // built at all. Letting any of these fall through to empty would import the configuration with
            // a hole in it.
            throw new IOException("Failed to resolve JCasC secret '" + secret + "' from Alibaba Cloud KMS", e);
        }
    }

    /**
     * Whether KMS answered that the secret does not exist, as opposed to the call never completing or
     * being rejected.
     *
     * <p>Walks the cause chain because {@link KmsSecretRetriever} rethrows whatever the SDK raised
     * wrapped in a {@link KmsPluginException}. A missing secret surfaces as a {@link TeaException}
     * carrying status 404 — KMS reports it as {@code Forbidden.ResourceNotFound} with a 404 status,
     * confirmed against a live endpoint. The status is the test rather than the exception type, because
     * the SDK also throws {@code TeaException} for reasons that never produced a response at all
     * (composing the request URL, converting a model, a bad proxy setting), and those carry no status;
     * a transport failure arrives as {@code TeaUnretryableException} with no status anywhere on the
     * chain.</p>
     */
    static boolean kmsSaidNotFound(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof TeaException && Integer.valueOf(NOT_FOUND).equals(((TeaException) t).getStatusCode())) {
                return true;
            }
        }
        return false;
    }
}
