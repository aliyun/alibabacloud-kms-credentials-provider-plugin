package org.jenkinsci.plugins.alibabacloudkms;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Properties;

/**
 * The environment {@link KmsAcceptanceIT} runs against, read from {@code kms-acceptance.properties}
 * on the test classpath.
 *
 * <p>That file is gitignored, because it names the KMS one particular machine's run writes to.
 * {@code kms-acceptance.template.properties} is the tracked half of the pair: it documents every key,
 * defaults the two naming prefixes and leaves every environment key blank. Copy it to
 * {@code kms-acceptance.properties} and fill the blanks in, or supply them per run with
 * {@code -D<key>=<value>}. With no local file the template is read instead, so an unconfigured run
 * fails on the first blank key rather than writing somewhere nobody chose. Nothing restricts which
 * endpoint may be named. The run only ever deletes the secrets it created itself, each tracked per
 * run, so aiming it somewhere unintended leaves that place with no residue rather than missing
 * data.</p>
 *
 * <p>{@link #load()} resolves every value eagerly. The run writes to a live gateway, so an incomplete
 * configuration has to fail before the first secret is created rather than partway through, where the
 * cleanup would be left with something to undo.</p>
 */
final class KmsAcceptanceConfig {

    private static final String RESOURCE = "/kms-acceptance.properties";
    private static final String TEMPLATE = "/kms-acceptance.template.properties";

    private static final String ENDPOINT = "kms.acceptance.endpoint";
    private static final String DKMS_INSTANCE_ID = "kms.acceptance.dkms-instance-id";
    private static final String REGION_ID = "kms.acceptance.region-id";
    private static final String RDS_INSTANCE_ID = "kms.acceptance.rds.instance-id";
    private static final String RDS_ACCOUNT_NAME = "kms.acceptance.rds.account-name";
    private static final String ECS_INSTANCE_ID = "kms.acceptance.ecs.instance-id";
    private static final String REDIS_INSTANCE_ID = "kms.acceptance.redis.instance-id";
    private static final String POLARDB_CLUSTER_ID = "kms.acceptance.polardb.cluster-id";
    private static final String POLARDB_DB_NAME = "kms.acceptance.polardb.db-name";
    private static final String SECRET_NAME_PREFIX = "kms.acceptance.secret-name-prefix";
    private static final String SELECTOR_TAG_PREFIX = "kms.acceptance.selector-tag-prefix";

    private final String endpoint;
    private final String dkmsInstanceId;
    private final String regionId;
    private final String rdsInstanceId;
    private final String rdsAccountName;
    private final String ecsInstanceId;
    private final String redisInstanceId;
    private final String polardbClusterId;
    private final String polardbDbName;
    private final String secretNamePrefix;
    private final String selectorTagPrefix;

    private KmsAcceptanceConfig(Properties file) {
        this.endpoint = required(file, ENDPOINT);
        this.dkmsInstanceId = required(file, DKMS_INSTANCE_ID);
        this.regionId = optional(file, REGION_ID);
        this.rdsInstanceId = required(file, RDS_INSTANCE_ID);
        this.rdsAccountName = required(file, RDS_ACCOUNT_NAME);
        this.ecsInstanceId = optional(file, ECS_INSTANCE_ID);
        this.redisInstanceId = optional(file, REDIS_INSTANCE_ID);
        this.polardbClusterId = optional(file, POLARDB_CLUSTER_ID);
        this.polardbDbName = optional(file, POLARDB_DB_NAME);
        this.secretNamePrefix = required(file, SECRET_NAME_PREFIX);
        this.selectorTagPrefix = required(file, SELECTOR_TAG_PREFIX);
    }

    static KmsAcceptanceConfig load() {
        return new KmsAcceptanceConfig(read());
    }

    private static Properties read() {
        Properties properties = new Properties();
        // Resolved against this class rather than the thread context classloader: under JenkinsRule the
        // context loader is the plugin uberClassLoader, which does not see target/test-classes.
        // RESOURCE is gitignored, so a fresh clone has only the template. Falling back to it keeps the two
        // naming prefixes defaulted and leaves every environment key blank, which is what makes an
        // unconfigured run fail in required() before it creates anything.
        for (String resource : new String[] {RESOURCE, TEMPLATE}) {
            try (InputStream in = KmsAcceptanceConfig.class.getResourceAsStream(resource)) {
                if (in == null) {
                    continue;
                }
                properties.load(in);
                break;
            } catch (IOException e) {
                throw new UncheckedIOException("Unable to read " + resource, e);
            }
        }
        return properties;
    }

    private static String required(Properties file, String key) {
        String value = optional(file, key);
        if (value == null) {
            throw new IllegalStateException("KMS acceptance has no value for " + key + ", expected in " + RESOURCE
                    + " (copy it from " + TEMPLATE + ") or as -D" + key);
        }
        return value;
    }

    /** Resolves an optional key the same way {@link #required} does, but returns {@code null} when absent. */
    private static String optional(Properties file, String key) {
        String value = trimToNull(System.getProperty(key));
        if (value == null) {
            value = trimToNull(file.getProperty(key));
        }
        return value;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    String endpoint() {
        return endpoint;
    }

    String dkmsInstanceId() {
        return dkmsInstanceId;
    }

    String regionId() {
        return regionId;
    }

    String rdsInstanceId() {
        return rdsInstanceId;
    }

    String rdsAccountName() {
        return rdsAccountName;
    }

    String ecsInstanceId() {
        return ecsInstanceId;
    }

    String redisInstanceId() {
        return redisInstanceId;
    }

    String polardbClusterId() {
        return polardbClusterId;
    }

    String polardbDbName() {
        return polardbDbName;
    }

    String secretNamePrefix() {
        return secretNamePrefix;
    }

    String selectorTagPrefix() {
        return selectorTagPrefix;
    }
}
