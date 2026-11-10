package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import com.aliyun.teaopenapi.models.Config;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;

/**
 * Builds an Alibaba Cloud KMS OpenAPI client.
 *
 * <p>Authentication uses the Alibaba Cloud default credential chain (environment variables such as
 * {@code ALIBABA_CLOUD_ACCESS_KEY_ID} / {@code ALIBABA_CLOUD_ACCESS_KEY_SECRET}, OIDC, ECS RAM role,
 * ...). No AccessKey is ever read from a Jenkins credential, so none is logged.</p>
 *
 * <p>Endpoints are not validated here. The ones this factory is given come either from an administrator
 * or, for {@code withAlibabaCloudKms}, from a job — and only the latter is checked, by
 * {@link KmsEndpointWhitelist} in the step that accepts it.</p>
 */
public final class KmsClientFactory {

    private static final Logger LOG = Logger.getLogger(KmsClientFactory.class.getName());

    private static final int TIMEOUT_MILLIS = 5_000;

    /**
     * The one default-credential-chain client, shared by every KMS client this factory builds.
     *
     * <p>Constructing {@code com.aliyun.credentials.Client} builds the whole provider chain eagerly,
     * and building {@code EcsRamRoleCredentialProvider} — which the chain always includes, even when
     * environment credentials are present — starts a {@code ScheduledThreadPoolExecutor} that polls
     * forever. Nothing can stop it again: {@code Config} keeps no reference to the provider, so the
     * provider's own {@code close()} is unreachable, and the live thread keeps the provider strongly
     * reachable so it is never collected either. Building one per call therefore leaked a thread per
     * call, and credential discovery calls this every 30 seconds.</p>
     *
     * <p>Held in a plain field rather than a static initialiser so that a failure to construct it
     * (nothing in the chain resolves) is retried on the next call instead of poisoning the class.</p>
     */
    private static volatile com.aliyun.credentials.Client defaultChain;

    private KmsClientFactory() {}

    public static Client createClient(String endpoint) {
        if (StringUtils.isBlank(endpoint)) {
            throw new KmsPluginException("KMS endpoint is not configured");
        }
        Config config = new Config();
        config.setEndpoint(endpoint);
        config.setConnectTimeout(TIMEOUT_MILLIS);
        config.setReadTimeout(TIMEOUT_MILLIS);
        config.setCredential(defaultChain());
        LOG.log(Level.FINE, "Using Alibaba Cloud default credential chain for KMS access");

        try {
            return new Client(config);
        } catch (Exception e) {
            throw new KmsPluginException("Failed to initialise Alibaba Cloud KMS client: " + e.getMessage(), e);
        }
    }

    private static com.aliyun.credentials.Client defaultChain() {
        com.aliyun.credentials.Client client = defaultChain;
        if (client == null) {
            synchronized (KmsClientFactory.class) {
                client = defaultChain;
                if (client == null) {
                    client = new com.aliyun.credentials.Client();
                    defaultChain = client;
                }
            }
        }
        return client;
    }
}
