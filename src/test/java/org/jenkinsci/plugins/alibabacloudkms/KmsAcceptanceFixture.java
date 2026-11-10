package org.jenkinsci.plugins.alibabacloudkms;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.CreateSecretRequest;
import com.aliyun.kms20160120.models.DeleteSecretRequest;
import com.aliyun.kms20160120.models.DescribeSecretRequest;
import com.aliyun.kms20160120.models.ListKeysRequest;
import com.aliyun.kms20160120.models.ListKeysResponse;
import com.aliyun.kms20160120.models.ListSecretsRequest;
import com.aliyun.kms20160120.models.ListSecretsResponse;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecret;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class KmsAcceptanceFixture implements AutoCloseable {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration DISCOVERY_INTERVAL = Duration.ofMillis(500);

    private final Client client;
    private final String endpoint;
    private final String dkmsInstanceId;
    private final String regionId;
    private final String ecsInstanceId;
    private final String redisInstanceId;
    private final String polardbClusterId;
    private final String polardbDbName;
    private final String runId;
    private final String prefix;
    private final String selectorTag;
    private final String selectorTagPrefix;
    private final String encryptionKeyId;
    private final List<String> createdSecrets = new ArrayList<>();

    private KmsAcceptanceFixture(Client client, KmsAcceptanceConfig config, String runId, String encryptionKeyId) {
        this.client = client;
        this.endpoint = config.endpoint();
        this.dkmsInstanceId = config.dkmsInstanceId();
        this.regionId = config.regionId();
        this.ecsInstanceId = config.ecsInstanceId();
        this.redisInstanceId = config.redisInstanceId();
        this.polardbClusterId = config.polardbClusterId();
        this.polardbDbName = config.polardbDbName();
        this.runId = runId;
        this.prefix = config.secretNamePrefix() + "-" + runId;
        this.selectorTag = config.selectorTagPrefix() + ":" + runId;
        this.selectorTagPrefix = config.selectorTagPrefix();
        this.encryptionKeyId = encryptionKeyId;
    }

    static KmsAcceptanceFixture create(KmsAcceptanceConfig config) {
        String runId = randomToken(6);
        try {
            Client client = KmsClientFactory.createClient(config.endpoint());
            return new KmsAcceptanceFixture(
                    client, config, runId, selectEncryptionKey(client, config.dkmsInstanceId()));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Unable to initialize the KMS acceptance client", e);
        }
    }

    /**
     * The endpoint the fixture's secrets were created against. The pipeline binds direct KMS secrets
     * through {@code withAlibabaCloudKms}, and reading the endpoint from here rather than passing the
     * configuration in again is what keeps the two from drifting apart.
     */
    String getEndpoint() {
        return endpoint;
    }

    private static String selectEncryptionKey(Client client, String instanceId) {
        String filters = "[{\"Key\":\"DKMSInstanceId\",\"Values\":[\"" + instanceId
                + "\"]},{\"Key\":\"KeySpec\",\"Values\":[\"Aliyun_AES_256\"]},{\"Key\":\"KeyState\",\"Values\":[\"Enabled\"]}"
                + ",{\"Key\":\"KeyUsage\",\"Values\":[\"ENCRYPT/DECRYPT\"]}]";
        try {
            ListKeysResponse response = client.listKeys(
                    new ListKeysRequest().setFilters(filters).setPageNumber(1).setPageSize(1));
            if (response != null
                    && response.getBody() != null
                    && response.getBody().getKeys() != null
                    && response.getBody().getKeys().getKey() != null
                    && !response.getBody().getKeys().getKey().isEmpty()) {
                String keyId = response.getBody().getKeys().getKey().get(0).getKeyId();
                if (keyId != null && !keyId.trim().isEmpty()) {
                    return keyId;
                }
            }
        } catch (Exception e) {
            throw new AssertionError("Unable to select an encryption key for KMS acceptance fixtures");
        }
        throw new AssertionError("No enabled AES-256 encryption key is available for KMS acceptance fixtures");
    }

    /**
     * A strict prefix of the {@code selectorTag} written on every fixture secret, and so a substring of
     * each of their tag keys, but never a tag key in its own right.
     *
     * <p>Configuring the provider with this rather than the full selector tag is what makes the
     * acceptance run depend on KMS matching {@code TagKey} as a case-sensitive substring. Passing the
     * full tag would succeed under exact matching too, and so would not notice a change in that
     * server-side behaviour - which is the assumption the default {@code jenkins:credentials} selector
     * rests on.</p>
     *
     * <p>The per-run {@code selectorTag} is derived from this by appending {@code ":" + runId} rather
     * than being configured alongside it, so no configuration can make the two unrelated and quietly
     * turn the substring match into an exact one.</p>
     */
    String getSelectorTagPrefix() {
        return selectorTagPrefix;
    }

    String getRunId() {
        return runId;
    }

    String secretName(String logicalName) {
        return prefix + "-" + logicalName;
    }

    String credentialId(String logicalName) {
        return prefix + "-credential-" + logicalName;
    }

    Map<String, String> credentialTags(String logicalName, String type) {
        Map<String, String> tags = new HashMap<>();
        tags.put(selectorTag, "true");
        tags.put("jenkins:credentials:id", credentialId(logicalName));
        tags.put("jenkins:credentials:type", type);
        tags.put("jenkins:credentials:scope", "GLOBAL");
        return tags;
    }

    void createTextSecret(String logicalName, String data, String secretType, Map<String, String> tags) {
        createSecret(logicalName, data, "text", secretType, tags, Collections.emptyMap());
    }

    void createRdsSecret(String logicalName, String data, Map<String, String> tags, String rdsInstanceId) {
        Map<String, String> extendedConfig = new LinkedHashMap<>();
        extendedConfig.put("SecretSubType", "SingleUser");
        extendedConfig.put("DBInstanceId", rdsInstanceId);
        createSecret(logicalName, data, "text", "Rds", tags, extendedConfig);
    }

    void createBinarySecret(String logicalName, byte[] data, Map<String, String> tags) {
        createSecret(
                logicalName, Base64.getEncoder().encodeToString(data), "binary", "Generic", tags,
                Collections.emptyMap());
    }

    /**
     * Creates an ECS login-password managed secret. KMS only calls the read-only DescribeInstances to
     * verify the instance exists and stores the supplied {UserName,Password} verbatim (GetSecretValue
     * normalizes it back to exactly those two fields), so this is the one managed type whose value the
     * test can assert as an exact round-trip. The name has to start with {@code acs/ecs/}: KMS rejects
     * any ECS secret whose name does not carry that reserved prefix.
     */
    void createEcsSecret(String logicalName, String userName, String password, Map<String, String> tags) {
        Map<String, String> extendedConfig = new LinkedHashMap<>();
        extendedConfig.put("SecretSubType", "Password");
        extendedConfig.put("RegionId", regionId);
        extendedConfig.put("InstanceId", ecsInstanceId);
        Map<String, String> secretData = new LinkedHashMap<>();
        secretData.put("UserName", userName);
        secretData.put("Password", password);
        createSecretNamed(
                ecsSecretName(logicalName),
                net.sf.json.JSONObject.fromObject(secretData).toString(),
                "text",
                "ECS",
                tags,
                extendedConfig);
    }

    /**
     * Creates a Redis double-account managed secret. KMS creates two real accounts on the instance
     * ({@code accountName} and {@code accountName_clone}) with server-generated passwords, so the test
     * can only assert the username it asked for and a non-empty password - not an exact value.
     * CloneAccountName is passed explicitly as {@code accountName + "_clone"} because KMS rejects any
     * other value. SecretData may be empty for this type; the passwords come from the created accounts.
     */
    void createRedisSecret(String logicalName, String accountName, Map<String, String> tags) {
        Map<String, String> extendedConfig = new LinkedHashMap<>();
        extendedConfig.put("SecretSubType", "DoubleUsers");
        extendedConfig.put("RegionId", regionId);
        extendedConfig.put("InstanceId", redisInstanceId);
        extendedConfig.put("AccountName", accountName);
        extendedConfig.put("CloneAccountName", accountName + "_clone");
        extendedConfig.put("AccountPrivilege", "RoleReadOnly");
        createSecret(logicalName, "", "text", "Redis", tags, extendedConfig);
    }

    /**
     * Creates a PolarDB double-account managed secret. Like Redis, KMS creates two real accounts with
     * server-generated passwords, so only the username and a non-empty password are assertable. For the
     * MySQL engine KMS additionally requires a per-DB privilege list whose length matches the DBName
     * list, and a Normal account type; both DBName and AccountPrivilege are single-valued here.
     */
    void createPolarDbSecret(String logicalName, String accountName, Map<String, String> tags) {
        Map<String, String> extendedConfig = new LinkedHashMap<>();
        extendedConfig.put("SecretSubType", "DoubleUsers");
        extendedConfig.put("RegionId", regionId);
        extendedConfig.put("DBClusterId", polardbClusterId);
        extendedConfig.put("DBType", "MySQL");
        extendedConfig.put("AccountType", "Normal");
        extendedConfig.put("AccountName", accountName);
        extendedConfig.put("CloneAccountName", accountName + "_clone");
        extendedConfig.put("DBName", polardbDbName);
        extendedConfig.put("AccountPrivilege", "ReadOnly");
        createSecret(logicalName, "", "text", "PolarDB", tags, extendedConfig);
    }

    String ecsSecretName(String logicalName) {
        return "acs/ecs/" + prefix + "-" + logicalName;
    }

    /**
     * A per-run unique database account base name: lowercase alphanumeric, starting with a letter, and
     * short enough that the derived {@code <base>_clone} account stays within the 16-character limit the
     * Redis and PolarDB services enforce on account names. Redis and PolarDB create these accounts for
     * real and do not remove them when the secret is deleted, so the name has to differ every run to
     * avoid colliding with residue from a previous one.
     */
    static String randomAccountBase() {
        return "kit" + randomAlphanumeric(5);
    }

    /** A per-run unique ECS login name; KMS stores and returns it verbatim. */
    static String randomLoginName() {
        return "kmsit" + randomAlphanumeric(6);
    }

    private static String randomAlphanumeric(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    void awaitDiscovery(Collection<String> secretNames) {
        Set<String> expected = new HashSet<>(secretNames);
        Instant deadline = Instant.now().plus(DISCOVERY_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            Set<String> discovered = discoverSecretNames();
            if (discovered.containsAll(expected)) {
                return;
            }
            try {
                Thread.sleep(DISCOVERY_INTERVAL.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("Interrupted while waiting for KMS acceptance fixture discovery");
            }
        }
        throw new AssertionError("Timed out waiting for KMS acceptance fixture discovery");
    }

    static String randomValue() {
        return "kms-it-" + randomToken(24);
    }

    static String sha256(String value) {
        return sha256(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    static String sha256(byte[] value) {
        try {
            return toHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable");
        }
    }

    /** Lowercase hex, matching the output the acceptance pipeline digests are compared against. */
    private static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16));
            hex.append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }

    @Override
    public void close() {
        List<String> failures = new ArrayList<>();
        for (int i = createdSecrets.size() - 1; i >= 0; i--) {
            String secretName = createdSecrets.get(i);
            try {
                client.deleteSecret(
                        new DeleteSecretRequest().setSecretName(secretName).setForceDeleteWithoutRecovery("true"));
            } catch (Exception e) {
                failures.add(secretName);
            }
        }
        if (!failures.isEmpty()) {
            throw new AssertionError("Failed to delete KMS acceptance fixtures: " + String.join(", ", failures));
        }
        for (String secretName : createdSecrets) {
            awaitDeletion(secretName);
        }
    }

    private void awaitDeletion(String secretName) {
        Instant deadline = Instant.now().plus(DISCOVERY_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            try {
                client.describeSecret(new DescribeSecretRequest().setSecretName(secretName));
            } catch (com.aliyun.tea.TeaException e) {
                if (Integer.valueOf(404).equals(e.getStatusCode())) {
                    return;
                }
                throw new AssertionError(
                        "Unable to verify KMS acceptance fixture deletion " + secretName + ": " + apiFailure(e));
            } catch (Exception e) {
                throw new AssertionError("Unable to verify KMS acceptance fixture deletion " + secretName);
            }
            try {
                Thread.sleep(DISCOVERY_INTERVAL.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("Interrupted while verifying KMS acceptance fixture deletion");
            }
        }
        throw new AssertionError("Timed out waiting for KMS acceptance fixture deletion " + secretName);
    }

    private void createSecret(
            String logicalName,
            String data,
            String dataType,
            String secretType,
            Map<String, String> tags,
            Map<String, ?> extendedConfig) {
        createSecretNamed(secretName(logicalName), data, dataType, secretType, tags, extendedConfig);
    }

    private void createSecretNamed(
            String secretName,
            String data,
            String dataType,
            String secretType,
            Map<String, String> tags,
            Map<String, ?> extendedConfig) {
        try {
            CreateSecretRequest request = new CreateSecretRequest()
                    .setDKMSInstanceId(dkmsInstanceId)
                    .setEncryptionKeyId(encryptionKeyId)
                    .setSecretName(secretName)
                    .setSecretData(data)
                    .setSecretDataType(dataType)
                    .setSecretType(secretType)
                    .setVersionId("v1");
            if (!extendedConfig.isEmpty()) {
                request.setExtendedConfig(extendedConfig);
            }
            if (!tags.isEmpty()) {
                List<Map<String, String>> tagList = tags.entrySet().stream()
                        .map(entry -> {
                            Map<String, String> tag = new LinkedHashMap<>();
                            tag.put("TagKey", entry.getKey());
                            tag.put("TagValue", entry.getValue());
                            return tag;
                        })
                        .collect(Collectors.toList());
                request.setTags(net.sf.json.JSONArray.fromObject(tagList).toString());
            }
            client.createSecret(request);
            createdSecrets.add(secretName);
        } catch (Exception e) {
            throw new AssertionError("Failed to create KMS acceptance fixture " + secretName + ": " + apiFailure(e));
        }
    }

    private static String apiFailure(Exception exception) {
        if (exception instanceof com.aliyun.tea.TeaException) {
            com.aliyun.tea.TeaException teaException = (com.aliyun.tea.TeaException) exception;
            String failure = "KMS code=" + teaException.getCode() + ", status=" + teaException.getStatusCode();
            if ("InvalidParameter".equals(teaException.getCode())) {
                String diagnostic = String.valueOf(teaException.getMessage()) + " " + teaException.getDescription();
                for (String field : Arrays.asList(
                        "DKMSInstanceId",
                        "SecretName",
                        "SecretData",
                        "SecretDataType",
                        "SecretType",
                        "VersionId",
                        "Tags",
                        "EncryptionKeyId")) {
                    if (diagnostic
                            .toLowerCase(java.util.Locale.ROOT)
                            .contains(field.toLowerCase(java.util.Locale.ROOT))) {
                        return failure + ", field=" + field;
                    }
                }
            }
            return failure;
        }
        return "KMS client exception=" + exception.getClass().getSimpleName();
    }

    private Set<String> discoverSecretNames() {
        try {
            ListSecretsResponse response = client.listSecrets(new ListSecretsRequest()
                    .setFilters(KmsCredentialsProvider.buildTagFilter(selectorTag))
                    .setPageNumber(1)
                    .setPageSize(100));
            Set<String> names = new HashSet<>();
            if (response == null
                    || response.getBody() == null
                    || response.getBody().getSecretList() == null
                    || response.getBody().getSecretList().getSecret() == null) {
                return names;
            }
            for (ListSecretsResponseBodySecretListSecret secret :
                    response.getBody().getSecretList().getSecret()) {
                if (secret != null && secret.getSecretName() != null) {
                    names.add(secret.getSecretName());
                }
            }
            return names;
        } catch (Exception e) {
            throw new AssertionError("Failed to discover KMS acceptance fixtures");
        }
    }

    private static String randomToken(int bytes) {
        byte[] token = new byte[bytes];
        RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token).toLowerCase(java.util.Locale.ROOT);
    }
}
