package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.ExtensionList;
import hudson.model.Result;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class KmsAcceptanceIT {

    @Rule public JenkinsRule jenkins = new JenkinsRule();

    private static final String ACCEPTANCE_ENABLED = "kms.acceptance";
    private static final List<String> CONFIGURATION_OVERRIDES = Arrays.asList(
            "ALIBABA_CLOUD_KMS_ENDPOINT",
            "ALIBABA_CLOUD_KMS_TAG_KEY",
            "jenkins.alibabacloud-kms.endpoint",
            "jenkins.alibabacloud-kms.tagKey");

    @Test
    public void validatesCredentialProjectionAndDirectBindings() throws Exception {
        KmsAcceptanceConfig config = verifyEnvironment();

        String stringValue = KmsAcceptanceFixture.randomValue();
        String fileValue = KmsAcceptanceFixture.randomValue();
        String username = KmsAcceptanceFixture.randomValue();
        String password = KmsAcceptanceFixture.randomValue();
        String rdsUsername = config.rdsAccountName();
        String rdsPassword = KmsAcceptanceFixture.randomValue();
        String passphrase = KmsAcceptanceFixture.randomValue();
        String certificatePassword = KmsAcceptanceFixture.randomValue();
        String directValue = KmsAcceptanceFixture.randomValue();
        byte[] directFileValue = randomBytes();
        String privateKey = generateSshPrivateKey();
        byte[] certificate = generatePkcs12(certificatePassword);

        try (KmsAcceptanceFixture fixture = KmsAcceptanceFixture.create(config)) {
            String stringSecret = fixture.secretName("string");
            String fileSecret = fixture.secretName("file");
            String usernameSecret = fixture.secretName("username");
            String rdsSecret = fixture.secretName("rds");
            String sshSecret = fixture.secretName("ssh");
            String passphraseSecret = fixture.secretName("ssh-passphrase");
            String certificateSecret = fixture.secretName("certificate");
            String certificatePasswordSecret = fixture.secretName("certificate-password");
            String directSecret = fixture.secretName("direct-secret");
            String directFileSecret = fixture.secretName("direct-file");

            fixture.createTextSecret("string", stringValue, "Generic", fixture.credentialTags("string", "string"));

            Map<String, String> fileTags = fixture.credentialTags("file", "secretFile");
            fileTags.put("jenkins:credentials:filename", "acceptance-file.txt");
            fixture.createTextSecret("file", fileValue, "Generic", fileTags);

            Map<String, String> usernameTags = fixture.credentialTags("username", "username");
            usernameTags.put("jenkins:credentials:username", username);
            fixture.createTextSecret("username", password, "Generic", usernameTags);

            Map<String, String> rdsTags = fixture.credentialTags("rds", "username");
            rdsTags.put("jenkins:credentials:auto-parse-secret", "true");
            fixture.createRdsSecret("rds", rdsPayload(rdsUsername, rdsPassword), rdsTags, config.rdsInstanceId());

            fixture.createTextSecret("ssh-passphrase", passphrase, "Generic", Collections.emptyMap());
            Map<String, String> sshTags = fixture.credentialTags("ssh", "sshUserPrivateKey");
            sshTags.put("jenkins:credentials:username", username);
            sshTags.put("jenkins:credentials:passphrase-id", passphraseSecret);
            fixture.createTextSecret("ssh", privateKey, "Generic", sshTags);

            fixture.createTextSecret("certificate-password", certificatePassword, "Generic", Collections.emptyMap());
            Map<String, String> certificateTags = fixture.credentialTags("certificate", "certificate");
            certificateTags.put("jenkins:credentials:password-id", certificatePasswordSecret);
            fixture.createTextSecret(
                    "certificate", Base64.getEncoder().encodeToString(certificate), "Generic", certificateTags);

            fixture.createTextSecret("direct-secret", directValue, "Generic", Collections.emptyMap());
            fixture.createBinarySecret("direct-file", directFileValue, Collections.emptyMap());

            fixture.awaitDiscovery(Arrays.asList(
                    stringSecret, fileSecret, usernameSecret, rdsSecret, sshSecret, certificateSecret));
            configureProvider(fixture);

            WorkflowJob job = jenkins.createProject(WorkflowJob.class, "kms-acceptance-" + fixture.getRunId());
            job.setDefinition(new CpsFlowDefinition(
                    pipeline(
                            fixture,
                            directSecret,
                            directFileSecret,
                            stringValue,
                            fileValue,
                            username,
                            password,
                            rdsUsername,
                            rdsPassword,
                            passphrase,
                            certificatePassword,
                            directValue,
                            directFileValue),
                    true));

            WorkflowRun build = jenkins.buildAndAssertSuccess(job);
            assertEquals(Result.SUCCESS, build.getResult());
            String log = JenkinsRule.getLog(build);
            assertTrue("KMS acceptance Pipeline did not complete", log.contains("KMS_ACCEPTANCE_OK"));
            assertSecretsAreAbsent(
                    log,
                    Arrays.asList(
                            stringValue,
                            fileValue,
                            username,
                            password,
                            rdsUsername,
                            rdsPassword,
                            passphrase,
                            certificatePassword,
                            directValue,
                            privateKey,
                            Base64.getEncoder().encodeToString(certificate),
                            Base64.getEncoder().encodeToString(directFileValue)));
        }
    }

    /**
     * Validates the contract {@link KmsManagedSecretRetriever} now relies on - that GetSecretValue returns
     * every managed type as a FLAT object, never the {@code {"Accounts":[...]}} shape that is only ever a
     * CreateSecret input - against three real managed secrets, one per type. Each is projected as a
     * {@code username} credential with {@code auto-parse-secret} and bound through {@code withCredentials},
     * so the value the pipeline sees is exactly what the retriever parsed off the live KMS response.
     *
     * <p>They are separate tests because each targets a different cloud instance and KMS can only manage
     * instances owned by the account behind the credentials: one type being unreachable must not mask the
     * others. Each is gated on its target being configured.</p>
     *
     * <p>ECS is read-only on the cloud side (KMS only calls DescribeInstances and stores the supplied
     * password), so its username and password are asserted as an exact round-trip. Redis and PolarDB are
     * not: KMS creates real double accounts with server-generated passwords and returns one of the two, so
     * only the username (base or its {@code _clone}) and a non-empty password are assertable.</p>
     */
    @Test
    public void validatesEcsManagedSecretFlatPayload() throws Exception {
        KmsAcceptanceConfig config = verifyEnvironment();
        Assume.assumeTrue("ECS managed-secret target is not configured", config.ecsInstanceId() != null);

        String user = KmsAcceptanceFixture.randomLoginName();
        String password = KmsAcceptanceFixture.randomValue();
        try (KmsAcceptanceFixture fixture = KmsAcceptanceFixture.create(config)) {
            Map<String, String> tags = fixture.credentialTags("ecs", "username");
            tags.put("jenkins:credentials:auto-parse-secret", "true");
            fixture.createEcsSecret("ecs", user, password, tags);
            fixture.awaitDiscovery(Collections.singletonList(fixture.ecsSecretName("ecs")));

            String body = "  withCredentials([usernamePassword(credentialsId: '"
                    + fixture.credentialId("ecs") + "', usernameVariable: 'U', passwordVariable: 'P')]) {\n"
                    + shellDigest("U", KmsAcceptanceFixture.sha256(user), false)
                    + shellDigest("P", KmsAcceptanceFixture.sha256(password), false)
                    + "  }\n";
            String log = runManagedPipeline(fixture, "ecs", body, "KMS_ECS_OK");
            assertSecretsAreAbsent(log, Collections.singletonList(password));
        }
    }

    @Test
    public void validatesRedisManagedSecretFlatPayload() throws Exception {
        KmsAcceptanceConfig config = verifyEnvironment();
        Assume.assumeTrue("Redis managed-secret target is not configured", config.redisInstanceId() != null);

        String account = KmsAcceptanceFixture.randomAccountBase();
        try (KmsAcceptanceFixture fixture = KmsAcceptanceFixture.create(config)) {
            Map<String, String> tags = fixture.credentialTags("redis", "username");
            tags.put("jenkins:credentials:auto-parse-secret", "true");
            fixture.createRedisSecret("redis", account, tags);
            fixture.awaitDiscovery(Collections.singletonList(fixture.secretName("redis")));

            runManagedPipeline(
                    fixture, "redis", managedAccountBlock(fixture.credentialId("redis"), account), "KMS_REDIS_OK");
        }
    }

    @Test
    public void validatesPolarDbManagedSecretFlatPayload() throws Exception {
        KmsAcceptanceConfig config = verifyEnvironment();
        Assume.assumeTrue(
                "PolarDB managed-secret target is not configured",
                config.polardbClusterId() != null && config.polardbDbName() != null);

        String account = KmsAcceptanceFixture.randomAccountBase();
        try (KmsAcceptanceFixture fixture = KmsAcceptanceFixture.create(config)) {
            Map<String, String> tags = fixture.credentialTags("polardb", "username");
            tags.put("jenkins:credentials:auto-parse-secret", "true");
            fixture.createPolarDbSecret("polardb", account, tags);
            fixture.awaitDiscovery(Collections.singletonList(fixture.secretName("polardb")));

            runManagedPipeline(
                    fixture,
                    "polardb",
                    managedAccountBlock(fixture.credentialId("polardb"), account),
                    "KMS_POLARDB_OK");
        }
    }

    /** Discovers the just-created credential, runs a one-binding pipeline over it, and asserts the marker. */
    private String runManagedPipeline(
            KmsAcceptanceFixture fixture, String logicalName, String body, String marker) throws Exception {
        configureProvider(fixture);
        WorkflowJob job =
                jenkins.createProject(WorkflowJob.class, "kms-" + logicalName + "-" + fixture.getRunId());
        job.setDefinition(new CpsFlowDefinition("node {\n" + body + "  echo '" + marker + "'\n}\n", true));
        WorkflowRun build = jenkins.buildAndAssertSuccess(job);
        assertEquals(Result.SUCCESS, build.getResult());
        String log = JenkinsRule.getLog(build);
        assertTrue(marker + " marker was not emitted", log.contains(marker));
        return log;
    }

    /**
     * Binds a double-account managed credential and asserts what is knowable about it: the username is
     * either the base account or its {@code _clone} (KMS returns one of the two), and the password is a
     * non-empty server-generated value. Neither the username nor which of the pair came back is a secret,
     * so both are compared in the clear rather than digested.
     */
    private static String managedAccountBlock(String credentialId, String account) {
        return "  withCredentials([usernamePassword(credentialsId: '" + credentialId
                + "', usernameVariable: 'U', passwordVariable: 'P')]) {\n"
                + "    sh '''set +x\n"
                + "test \"$U\" = '" + account + "' -o \"$U\" = '" + account + "_clone'\n"
                + "test -n \"$P\"\n"
                + "'''\n"
                + "  }\n";
    }

    /**
     * Loads the environment configuration and asserts the preconditions that must hold before anything
     * is written to a live gateway. {@link KmsAcceptanceConfig#load()} resolves every value eagerly, so a
     * missing endpoint, DKMS instance, RDS target or naming prefix fails here rather than partway
     * through the run.
     */
    private static KmsAcceptanceConfig verifyEnvironment() {
        assertEquals("true", System.getProperty(ACCEPTANCE_ENABLED));
        KmsAcceptanceConfig config = KmsAcceptanceConfig.load();
        String operatingSystem = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        assertTrue(
                "KMS acceptance tests require a POSIX runner",
                operatingSystem.contains("linux") || operatingSystem.contains("mac"));
        for (String override : CONFIGURATION_OVERRIDES) {
            String value = override.startsWith("ALIBABA_") ? System.getenv(override) : System.getProperty(override);
            assertFalse(
                    "KMS acceptance rejects global configuration overrides", value != null && !value.trim().isEmpty());
        }
        return config;
    }

    /**
     * Points the plugin at the environment the fixture just wrote to, so that discovery finds exactly
     * the secrets this run created and nothing else that the gateway may already hold. Both values come
     * off the fixture because both have to agree with it.
     */
    private static void configureProvider(KmsAcceptanceFixture fixture) {
        KmsGlobalConfiguration configuration = KmsGlobalConfiguration.get();
        configuration.setEndpoint(fixture.getEndpoint());
        configuration.setTagKey(fixture.getSelectorTagPrefix());
        ExtensionList.lookupSingleton(KmsCredentialsProvider.class).refreshCredentials();
    }

    private static String pipeline(
            KmsAcceptanceFixture fixture,
            String directSecret,
            String directFileSecret,
            String stringValue,
            String fileValue,
            String username,
            String password,
            String rdsUsername,
            String rdsPassword,
            String passphrase,
            String certificatePassword,
            String directValue,
            byte[] directFileValue) {
        String stringCredential = fixture.credentialId("string");
        String fileCredential = fixture.credentialId("file");
        String usernameCredential = fixture.credentialId("username");
        String rdsCredential = fixture.credentialId("rds");
        String sshCredential = fixture.credentialId("ssh");
        String certificateCredential = fixture.credentialId("certificate");
        StringBuilder script = new StringBuilder();
        script.append("node {\n");
        script.append("  withCredentials([string(credentialsId: '")
                .append(stringCredential)
                .append("', variable: 'STRING_VALUE')]) {\n")
                .append(shellDigest("STRING_VALUE", KmsAcceptanceFixture.sha256(stringValue), false))
                .append("  }\n");
        script.append("  withCredentials([file(credentialsId: '")
                .append(fileCredential)
                .append("', variable: 'FILE_VALUE')]) {\n")
                .append(shellDigest("FILE_VALUE", KmsAcceptanceFixture.sha256(fileValue), true))
                .append("  }\n");
        script.append("  withCredentials([usernamePassword(credentialsId: '")
                .append(usernameCredential)
                .append("', usernameVariable: 'USERNAME_VALUE', passwordVariable: 'PASSWORD_VALUE')]) {\n")
                .append(shellDigest("USERNAME_VALUE", KmsAcceptanceFixture.sha256(username), false))
                .append(shellDigest("PASSWORD_VALUE", KmsAcceptanceFixture.sha256(password), false))
                .append("  }\n");
        script.append("  withCredentials([usernamePassword(credentialsId: '")
                .append(rdsCredential)
                .append("', usernameVariable: 'RDS_USERNAME', passwordVariable: 'RDS_PASSWORD')]) {\n")
                .append(shellDigest("RDS_USERNAME", KmsAcceptanceFixture.sha256(rdsUsername), false))
                .append(shellDigest("RDS_PASSWORD", KmsAcceptanceFixture.sha256(rdsPassword), false))
                .append("  }\n");
        script.append("  withCredentials([sshUserPrivateKey(credentialsId: '")
                .append(sshCredential)
                .append(
                        "', keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USERNAME', passphraseVariable: 'SSH_PASSPHRASE')]) {\n")
                .append("    sh '''set +x\nssh-keygen -y -f \"$SSH_KEY\" >/dev/null\n")
                .append("test \"$(printf %s \"$SSH_USERNAME\" | openssl dgst -sha256 -r | cut -d ' ' -f1)\" = '")
                .append(KmsAcceptanceFixture.sha256(username))
                .append("'\n")
                .append("test \"$(printf %s \"$SSH_PASSPHRASE\" | openssl dgst -sha256 -r | cut -d ' ' -f1)\" = '")
                .append(KmsAcceptanceFixture.sha256(passphrase))
                .append("'\n'''\n  }\n");
        script.append("  withCredentials([certificate(credentialsId: '")
                .append(certificateCredential)
                .append("', keystoreVariable: 'CERTIFICATE_STORE', passwordVariable: 'CERTIFICATE_PASSWORD')]) {\n")
                .append(
                        "    sh '''set +x\nkeytool -list -storetype PKCS12 -keystore \"$CERTIFICATE_STORE\" -storepass \"$CERTIFICATE_PASSWORD\" >/dev/null\n")
                .append(
                        "test \"$(printf %s \"$CERTIFICATE_PASSWORD\" | openssl dgst -sha256 -r | cut -d ' ' -f1)\" = '")
                .append(KmsAcceptanceFixture.sha256(certificatePassword))
                .append("'\n'''\n  }\n");
        script.append("  withAlibabaCloudKms(endpoint: '")
                .append(fixture.getEndpoint())
                .append("', secrets: [[secretType: 'Secret', name: '")
                .append(directSecret)
                .append("', envVariable: 'DIRECT_SECRET']]) {\n")
                .append(shellDigest("DIRECT_SECRET", KmsAcceptanceFixture.sha256(directValue), false))
                .append("  }\n");
        script.append("  def directFile\n")
                .append("  withAlibabaCloudKms(endpoint: '")
                .append(fixture.getEndpoint())
                .append("', secrets: [[secretType: 'File', name: '")
                .append(directFileSecret)
                .append("', envVariable: 'DIRECT_FILE']]) {\n")
                .append("    directFile = env.DIRECT_FILE\n")
                .append(shellDigest("DIRECT_FILE", KmsAcceptanceFixture.sha256(directFileValue), true))
                .append("  }\n")
                .append("  if (fileExists(directFile)) { error 'direct KMS file fixture was not deleted' }\n")
                .append("  echo 'KMS_ACCEPTANCE_OK'\n")
                .append("}\n");
        return script.toString();
    }

    private static String shellDigest(String variable, String digest, boolean file) {
        String command = file
                ? "openssl dgst -sha256 -r \"$" + variable + "\""
                : "printf %s \"$" + variable + "\" | openssl dgst -sha256 -r";
        return "    sh '''set +x\ntest \"$(" + command + " | cut -d ' ' -f1)\" = '" + digest + "'\n'''\n";
    }

    private static String rdsPayload(String username, String password) {
        Map<String, String> account = new HashMap<>();
        account.put("AccountName", username);
        account.put("AccountPassword", password);
        return net.sf.json.JSONObject.fromObject(
                        Collections.singletonMap("Accounts", Collections.singletonList(account)))
                .toString();
    }

    private static byte[] randomBytes() {
        byte[] data = new byte[32];
        new java.security.SecureRandom().nextBytes(data);
        return data;
    }

    private static String generateSshPrivateKey() throws IOException {
        Path directory = Files.createTempDirectory("kms-acceptance-ssh-");
        Path key = directory.resolve("id_ed25519");
        try {
            runCommand(
                    Arrays.asList("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key.toString()),
                    "Unable to generate the SSH fixture");
            return new String(Files.readAllBytes(key), StandardCharsets.UTF_8);
        } finally {
            Files.deleteIfExists(key);
            Files.deleteIfExists(Paths.get(key + ".pub"));
            Files.deleteIfExists(directory);
        }
    }

    private static byte[] generatePkcs12(String password) throws IOException {
        Path keyStore = Files.createTempFile("kms-acceptance-certificate-", ".p12");
        Files.delete(keyStore);
        try {
            String keytool =
                    Paths.get(System.getProperty("java.home"), "bin", "keytool").toString();
            runCommand(
                    Arrays.asList(
                            keytool,
                            "-genkeypair",
                            "-alias",
                            "acceptance",
                            "-keyalg",
                            "RSA",
                            "-keysize",
                            "2048",
                            "-validity",
                            "1",
                            "-storetype",
                            "PKCS12",
                            "-keystore",
                            keyStore.toString(),
                            "-storepass",
                            password,
                            "-keypass",
                            password,
                            "-dname",
                            "CN=KMS Acceptance",
                            "-noprompt"),
                    "Unable to generate the certificate fixture");
            return Files.readAllBytes(keyStore);
        } finally {
            Files.deleteIfExists(keyStore);
        }
    }

    private static void runCommand(List<String> command, String failure) throws IOException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        try {
            if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                throw new AssertionError(failure);
            }
            InputStream output = process.getInputStream();
            byte[] buffer = new byte[4096];
            while (output.read(buffer) != -1) {
                // Drain the combined output so the process is never left blocked on a full pipe.
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(failure);
        }
    }

    private static void assertSecretsAreAbsent(String log, List<String> values) {
        for (String value : values) {
            assertFalse("KMS acceptance log exposed fixture material", log.contains(value));
        }
    }
}
