package org.jenkinsci.plugins.alibabacloudkms;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.ObjectUtils.firstNonNull;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GetSecretValueResponseBody;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.Util;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import hudson.slaves.WorkspaceList;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.YesNoMaybe;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.workflow.steps.BodyInvoker;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Binds Alibaba Cloud KMS secrets to environment variables for the duration of a build.
 *
 * <p>The endpoint is inherited from {@link KmsGlobalConfiguration} unless overridden on the step.
 * Secret values are masked in the build log on a best-effort basis.</p>
 */
public class KmsStep extends Step {

    private static final Logger LOG = Logger.getLogger(KmsStep.class.getName());

    private static final String BINARY_DATA_TYPE = "binary";

    private final List<KmsSecret> secrets;
    private String endpoint;

    @DataBoundConstructor
    public KmsStep(List<KmsSecret> secrets) {
        this.secrets = secrets;
    }

    public List<KmsSecret> getSecrets() {
        return secrets;
    }

    public String getEndpoint() {
        return endpoint;
    }

    @DataBoundSetter
    public void setEndpoint(String endpoint) {
        this.endpoint = Util.fixEmpty(endpoint);
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        KmsGlobalConfiguration configuration = KmsGlobalConfiguration.get();
        if (endpoint != null) {
            // Only an endpoint a job named is checked. One an administrator configured globally is not:
            // it arrives through an Overall/Administer gated page, an environment variable or a system
            // property, so whoever set it was already trusted with where the controller talks to.
            KmsEndpointWhitelist.requireAllowed(endpoint, configuration.getStepEndpointWhitelist());
        }
        String resolvedEndpoint = firstNonNull(endpoint, configuration.getEndpoint());
        if (StringUtils.isEmpty(resolvedEndpoint)) {
            throw new KmsPluginException("No Alibaba Cloud KMS endpoint configured, set one globally or on the step");
        }
        requireBoundNames(secrets);

        return new ExecutionImpl(context, resolvedEndpoint, secrets);
    }

    /**
     * The descriptor's form validation is display-only and is bypassed outright by a job configured
     * through JCasC, an edited config.xml or an older pipeline, so the same blanks are refused here.
     * Doing it before the execution is even built matters twice over: an unusable variable name is a
     * configuration error rather than a KMS one, and without this the value is fetched into memory
     * first and the failure surfaces as a bare NullPointerException from inside EnvVars during body
     * expansion, naming neither the step nor the offending entry.
     */
    private static void requireBoundNames(List<KmsSecret> secrets) {
        if (secrets == null) {
            return;
        }
        for (int i = 0; i < secrets.size(); i++) {
            KmsSecret secret = secrets.get(i);
            String entry = "secrets[" + i + "]";
            if (StringUtils.isBlank(secret.getName())) {
                throw new KmsPluginException(entry + " has no secret name");
            }
            if (StringUtils.isBlank(secret.getEnvVariable())) {
                throw new KmsPluginException(entry + " (" + secret.getName() + ") has no environment variable");
            }
        }
    }

    /**
     * Runs off the CPS VM thread: resolving secrets is blocking network IO against KMS, and the
     * controller has a single CPS VM thread shared by every pipeline.
     */
    static class ExecutionImpl extends GeneralNonBlockingStepExecution {

        private static final long serialVersionUID = 1L;

        private final String endpoint;
        private final List<KmsSecret> kmsSecrets;

        ExecutionImpl(StepContext context, String endpoint, List<KmsSecret> kmsSecrets) {
            super(context);
            this.endpoint = endpoint;
            this.kmsSecrets = kmsSecrets;
        }

        @Override
        public boolean start() throws Exception {
            run(this::doStart);
            return false;
        }

        private void doStart() throws Exception {
            StepContext context = getContext();
            Run<?, ?> run = context.get(Run.class);

            Client client = KmsClientFactory.createClient(endpoint);
            Map<String, String> secretEnvironment = new LinkedHashMap<>();
            Map<String, String> publicEnvironment = new LinkedHashMap<>();
            Collection<String> sensitiveValues = new ArrayList<>();
            List<FilePath> secretFiles = new ArrayList<>();
            try {
                resolveSecrets(client, context, secretEnvironment, publicEnvironment, sensitiveValues, secretFiles);
            } catch (Exception e) {
                deleteQuietly(secretFiles);
                throw e;
            }

            BodyInvoker invoker = context.newBodyInvoker().withCallback(new SecretFileCleanup(secretFiles));

            invoker.withContexts(
                    EnvironmentExpander.merge(
                            context.get(EnvironmentExpander.class),
                            new KmsEnvironmentExpander(secretEnvironment, publicEnvironment)),
                    BodyInvoker.mergeConsoleLogFilters(
                            context.get(ConsoleLogFilter.class),
                            new MaskingConsoleLogFilter(run.getCharset().name(), sensitiveValues)));
            invoker.start();
        }

        /**
         * Deletes secret material written to the agent once the body finishes, so plaintext does not
         * outlive the scope of the step on a shared or reused agent.
         */
        private final class SecretFileCleanup extends TailCall {

            private static final long serialVersionUID = 1L;

            private final List<FilePath> secretFiles;

            SecretFileCleanup(List<FilePath> secretFiles) {
                this.secretFiles = secretFiles;
            }

            @Override
            protected void finished(StepContext context) {
                deleteQuietly(secretFiles);
            }
        }

        private static void deleteQuietly(List<FilePath> secretFiles) {
            for (FilePath file : secretFiles) {
                try {
                    file.delete();
                } catch (IOException | InterruptedException e) {
                    if (e instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    LOG.log(Level.WARNING, "Failed to delete secret file " + file.getRemote(), e);
                }
            }
        }

        private void resolveSecrets(
                Client client,
                StepContext context,
                Map<String, String> secretEnvironment,
                Map<String, String> publicEnvironment,
                Collection<String> sensitiveValues,
                List<FilePath> secretFiles)
                throws Exception {
            if (kmsSecrets == null || kmsSecrets.isEmpty()) {
                return;
            }

            for (KmsSecret secret : kmsSecrets) {
                GetSecretValueResponseBody body =
                        KmsSecretRetriever.fetchSecretValue(client, secret.getName(), secret.getVersion());
                String data = body.getSecretData();
                if (data == null) {
                    throw new KmsPluginException("Secret '" + secret.getName() + "' returned no data");
                }

                // Binary secrets are returned base64 encoded; mask the raw payload either way.
                sensitiveValues.add(data);

                if (secret.isFile()) {
                    FilePath workspace =
                            requireNonNull(context.get(FilePath.class), "A file secret requires a `node` context");
                    FilePath outFile = createSecretFile(workspace, secret);
                    // Registered before any plaintext is written: a failure inside writeSecretContent
                    // would otherwise leave the file behind, because the cleanup below only sees what
                    // is in this list.
                    secretFiles.add(outFile);
                    writeSecretContent(outFile, body, data);
                    // The variable holds a path, not secret material, so it is not marked sensitive;
                    // the payload itself is still masked via sensitiveValues above.
                    publicEnvironment.put(secret.getEnvVariable(), outFile.getRemote());
                } else {
                    secretEnvironment.put(secret.getEnvVariable(), data);
                    bindManagedPair(secret, body, data, secretEnvironment, sensitiveValues);
                }
            }
        }

        /**
         * Managed secrets (Rds, Redis, PolarDB, ECS, RAMCredentials) hold a JSON account/password pair
         * rather than a bare string. The whole payload stays bound to the declared variable so existing
         * pipelines keep working; the two fields are exposed alongside it as {@code <VAR>_USERNAME} and
         * {@code <VAR>_PASSWORD}. Both are masked, so a RAM secret's AccessKeyId is not echoed here,
         * unlike under {@code withCredentials}, which masks the password alone.
         */
        private static void bindManagedPair(
                KmsSecret secret,
                GetSecretValueResponseBody body,
                String data,
                Map<String, String> secretEnvironment,
                Collection<String> sensitiveValues) {
            Optional<ManagedSecretType> managedType = ManagedSecretType.from(body.getSecretType());
            if (!managedType.isPresent()) {
                return;
            }
            KmsManagedSecretRetriever.Value value =
                    KmsManagedSecretRetriever.parse(secret.getName(), data, managedType.get());
            String usernameVariable = secret.getEnvVariable() + "_USERNAME";
            String passwordVariable = secret.getEnvVariable() + "_PASSWORD";
            secretEnvironment.put(usernameVariable, value.username());
            secretEnvironment.put(passwordVariable, value.password());
            sensitiveValues.add(value.username());
            sensitiveValues.add(value.password());
        }

        /**
         * Creates an empty destination under the workspace's {@code @tmp} sibling rather than in the
         * workspace itself, so the plaintext is out of reach of workspace browsing and of an
         * {@code archiveArtifacts '**&#47;*'} running inside the same step. The directory is
         * owner-only, which is what covers the window between creation and the
         * {@code chmod} after the content is written — mirroring credentials-binding's own
         * {@code UnbindableDir}.
         */
        private static FilePath createSecretFile(FilePath workspace, KmsSecret secret) throws Exception {
            FilePath dir = secretFileDir(workspace);
            dir.mkdirs();
            dir.chmod(0700);
            return dir.createTempFile("kms-" + escapeFileNameComponent(secret.getName()) + "-", ".dat");
        }

        /**
         * Percent-encodes everything outside {@code [A-Za-z0-9._-]}, so an arbitrary KMS secret name is
         * safe as a {@link FilePath#createTempFile} prefix. A KMS name may contain {@code /}, which would
         * otherwise split the prefix into a path and make the underlying {@code File} binding fail with an
         * opaque IOException, and may contain characters Windows reserves — including {@code *}, which
         * {@link java.net.URLEncoder} leaves alone. Encoding {@code %} itself is what keeps two different
         * names from collapsing onto the same prefix.
         */
        static String escapeFileNameComponent(String name) {
            StringBuilder escaped = new StringBuilder(name.length() * 3);
            for (byte b : name.getBytes(StandardCharsets.UTF_8)) {
                int c = b & 0xFF;
                if ((c >= 'a' && c <= 'z')
                        || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9')
                        || c == '.'
                        || c == '_'
                        || c == '-') {
                    escaped.append((char) c);
                } else {
                    escaped.append(String.format("%%%02X", c));
                }
            }
            return escaped.toString();
        }

        private static void writeSecretContent(FilePath outFile, GetSecretValueResponseBody body, String data)
                throws Exception {
            if (BINARY_DATA_TYPE.equalsIgnoreCase(body.getSecretDataType())) {
                try (OutputStream stream = outFile.write()) {
                    stream.write(Base64.getDecoder().decode(data));
                }
            } else {
                outFile.write(data, StandardCharsets.UTF_8.name());
            }
            // Applied after the write, not before: on a Windows agent a 0400 mask clears the write bit
            // and the write itself would fail.
            outFile.chmod(0400);
        }

        private static FilePath secretFileDir(FilePath workspace) throws IOException {
            FilePath tempDir = WorkspaceList.tempDir(workspace);
            if (tempDir == null) {
                throw new IOException("Unable to resolve a temporary directory next to " + workspace);
            }
            return tempDir.child("kms-secrets");
        }
    }

    @Extension(dynamicLoadable = YesNoMaybe.YES, optional = true)
    public static class DescriptorImpl extends StepDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return "Bind Alibaba Cloud KMS secrets to environment variables";
        }

        @Override
        public String getFunctionName() {
            return "withAlibabaCloudKms";
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Collections.singleton(Run.class);
        }
    }
}
