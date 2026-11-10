package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import org.junit.After;
import org.junit.Test;

/**
 * Pins how {@link KmsAcceptanceIT} picks its environment. These are the only tests of that logic
 * that do not need a live KMS, which is what makes the behaviour cheap to keep honest.
 */
public class KmsAcceptanceConfigTest {

    private static final List<String> KEYS = Arrays.asList(
            "kms.acceptance.endpoint",
            "kms.acceptance.dkms-instance-id",
            "kms.acceptance.rds.instance-id",
            "kms.acceptance.rds.account-name",
            "kms.acceptance.secret-name-prefix",
            "kms.acceptance.selector-tag-prefix");

    /** Every key that names a cloud resource, as opposed to the two that only namespace a run's own. */
    private static final List<String> ENVIRONMENT_KEYS = Arrays.asList(
            "kms.acceptance.endpoint",
            "kms.acceptance.dkms-instance-id",
            "kms.acceptance.region-id",
            "kms.acceptance.rds.instance-id",
            "kms.acceptance.rds.account-name",
            "kms.acceptance.ecs.instance-id",
            "kms.acceptance.redis.instance-id",
            "kms.acceptance.polardb.cluster-id",
            "kms.acceptance.polardb.db-name");

    @After
    public void clearOverrides() {
        KEYS.forEach(System::clearProperty);
    }

    /**
     * Pins the keys a test must not inherit from whatever the local, gitignored
     * {@code kms-acceptance.properties} happens to name, so every test below means the same thing on a
     * fresh clone and on a machine already configured for a real run. The values name no reachable KMS.
     */
    private static void overrideEnvironment() {
        System.setProperty("kms.acceptance.endpoint", "kms.example.aliyuncs.com");
        System.setProperty("kms.acceptance.dkms-instance-id", "kst-example");
        System.setProperty("kms.acceptance.rds.instance-id", "rm-example");
        System.setProperty("kms.acceptance.rds.account-name", "account-example");
    }

    /**
     * The template is the tracked half of the pair, so it is both what a fresh clone ships and what the
     * loader falls back to when nobody has created the local file. It has to name no environment: a blank
     * key fails the run in {@code required()} before the fixture creates anything, whereas a value here
     * would aim every unconfigured run at a real gateway nobody chose. Asserting against the tracked file
     * rather than the local one is what makes this hold on any machine.
     */
    @Test
    public void theTrackedTemplateNamesNoEnvironment() throws Exception {
        Properties template = new Properties();
        try (InputStream in =
                KmsAcceptanceConfigTest.class.getResourceAsStream("/kms-acceptance.template.properties")) {
            assertNotNull("the template is the tracked fallback, so it must be on the test classpath", in);
            template.load(in);
        }

        for (String key : ENVIRONMENT_KEYS) {
            assertTrue(key + " must stay listed in the template so the key is documented", template.containsKey(key));
            String value = template.getProperty(key);
            assertTrue(key + " must stay blank in the tracked template, but was '" + value + "'",
                    value == null || value.trim().isEmpty());
        }

        String secretNamePrefix = template.getProperty("kms.acceptance.secret-name-prefix");
        String selectorTagPrefix = template.getProperty("kms.acceptance.selector-tag-prefix");
        assertNotNull("kms.acceptance.secret-name-prefix must stay listed in the template", secretNamePrefix);
        assertNotNull("kms.acceptance.selector-tag-prefix must stay listed in the template", selectorTagPrefix);
        // The two namespace keys are the exception: they carry no environment, and defaulting them in the
        // tracked file is what lets a residue check find a run's leftovers by tag afterwards.
        assertFalse(secretNamePrefix.trim().isEmpty());
        assertFalse(selectorTagPrefix.trim().isEmpty());
    }

    @Test
    public void namespaceKeysStillDefaultFromTheFile() {
        overrideEnvironment();

        KmsAcceptanceConfig config = KmsAcceptanceConfig.load();

        // These two are what keep a run's secrets distinguishable from everybody else's on a shared
        // gateway, and what let a residue check find leftovers by tag afterwards, so they stay
        // defaulted in the file rather than being supplied per run.
        assertFalse(config.secretNamePrefix().trim().isEmpty());
        assertFalse(config.selectorTagPrefix().trim().isEmpty());
    }

    /**
     * The run is meant to be reusable against any environment the credentials can reach, so the endpoint
     * is an ordinary overridable value rather than one checked against an allowlist. Asserting that an
     * unrelated region is taken verbatim is what keeps it that way.
     */
    @Test
    public void systemPropertyOverridesReachEveryKeyIncludingTheEndpoint() {
        System.setProperty("kms.acceptance.endpoint", "kms.cn-shanghai.aliyuncs.com");
        System.setProperty("kms.acceptance.dkms-instance-id", "kst-overridden");
        System.setProperty("kms.acceptance.rds.instance-id", "rm-overridden");
        System.setProperty("kms.acceptance.rds.account-name", "account-overridden");
        System.setProperty("kms.acceptance.secret-name-prefix", "prefix-overridden");
        System.setProperty("kms.acceptance.selector-tag-prefix", "tag-overridden");

        KmsAcceptanceConfig config = KmsAcceptanceConfig.load();

        assertEquals("kms.cn-shanghai.aliyuncs.com", config.endpoint());
        assertEquals("kst-overridden", config.dkmsInstanceId());
        assertEquals("rm-overridden", config.rdsInstanceId());
        assertEquals("account-overridden", config.rdsAccountName());
        assertEquals("prefix-overridden", config.secretNamePrefix());
        assertEquals("tag-overridden", config.selectorTagPrefix());
    }

    @Test
    public void blankOverrideFallsBackToTheFile() {
        overrideEnvironment();
        String fromFile = KmsAcceptanceConfig.load().secretNamePrefix();
        System.setProperty("kms.acceptance.secret-name-prefix", "   ");

        assertEquals(fromFile, KmsAcceptanceConfig.load().secretNamePrefix());
    }

    @Test
    public void overrideIsTrimmed() {
        overrideEnvironment();
        System.setProperty("kms.acceptance.endpoint", "  kms.cn-shanghai.aliyuncs.com  ");

        assertEquals("kms.cn-shanghai.aliyuncs.com", KmsAcceptanceConfig.load().endpoint());
    }
}
