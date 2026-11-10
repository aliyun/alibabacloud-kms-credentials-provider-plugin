package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.model.Result;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class KmsStepTest {

    @Rule public JenkinsRule jenkins = new JenkinsRule();

    private static final String ENDPOINT = "kms.cn-hangzhou.aliyuncs.com";

    @Test
    public void executionDoesNotRunOnTheCpsVmThread() {
        // Resolving secrets is blocking network IO against KMS, and the controller has a single CPS VM
        // thread shared by every pipeline. Doing it inside start() would stall all of them for the
        // duration of a KMS timeout.
        assertTrue(
                "KmsStep.ExecutionImpl must hand its blocking work to a utility thread",
                GeneralNonBlockingStepExecution.class.isAssignableFrom(KmsStep.ExecutionImpl.class));
    }

    @Test
    public void bodyRunsWithoutSecretsAndTouchesNoNetwork() throws Exception {
        WorkflowJob job = jenkins.createProject(WorkflowJob.class, "kms-step-empty");
        job.setDefinition(new CpsFlowDefinition(
                "withAlibabaCloudKms(endpoint: '" + ENDPOINT + "', secrets: []) {\n" + "  echo 'BODY_RAN'\n" + "}\n",
                true));

        WorkflowRun build = jenkins.buildAndAssertSuccess(job);

        jenkins.assertLogContains("BODY_RAN", build);
    }

    @Test
    public void aGloballyConfiguredEndpointIsNotWhitelisted() throws Exception {
        // The whitelist bounds what a job may name, not what an administrator configured: the global
        // endpoint arrives through an Overall/Administer gated page, an environment variable or a system
        // property, so whoever set it was already trusted with where the controller talks to.
        KmsGlobalConfiguration.get().setEndpoint("kms.internal.example.com");

        WorkflowJob job = jenkins.createProject(WorkflowJob.class, "kms-step-global-endpoint");
        job.setDefinition(new CpsFlowDefinition(
                "withAlibabaCloudKms(secrets: []) {\n" + "  echo 'BODY_RAN'\n" + "}\n", true));

        WorkflowRun build = jenkins.buildAndAssertSuccess(job);

        jenkins.assertLogContains("BODY_RAN", build);
    }

    @Test
    public void failureInBackgroundExecutionReachesTheBuildResult() throws Exception {
        // kms.invalid is reserved to never resolve, so the background fetch fails at DNS rather than
        // depending on the network or on ambient default-chain credentials. The whitelist is opened up
        // because the subject here is a failure on the utility thread, not endpoint validation.
        KmsGlobalConfiguration.get().setStepEndpointWhitelist("*");
        WorkflowJob job = jenkins.createProject(WorkflowJob.class, "kms-step-unreachable");
        job.setDefinition(new CpsFlowDefinition(
                "withAlibabaCloudKms(endpoint: 'kms.invalid',"
                        + " secrets: [[secretType: 'Secret', name: 'any-secret', envVariable: 'ANY_SECRET']]) {\n"
                        + "  echo 'BODY_MUST_NOT_RUN'\n"
                        + "}\n",
                true));

        WorkflowRun build = jenkins.buildAndAssertStatus(Result.FAILURE, job);

        String log = JenkinsRule.getLog(build);
        assertTrue(
                "the cause raised on the utility thread must surface in the build log: " + log,
                log.contains("kms.invalid"));
        assertFalse("the body must not run when binding failed", log.contains("BODY_MUST_NOT_RUN"));
    }

    @Test
    public void anEndpointOutsideTheWhitelistFailsBeforeAnyConnection() throws Exception {
        // Naming an endpoint is the one part of a KMS call a pipeline author controls with Job/Configure
        // alone, far below Overall/Administer. Unbounded, that makes the controller open a connection to a
        // host of the author's choosing, signed with the controller's own Alibaba Cloud identity, and
        // reflects that host's reply into the build log.
        WorkflowJob job = jenkins.createProject(WorkflowJob.class, "kms-step-not-whitelisted");
        job.setDefinition(new CpsFlowDefinition(
                "withAlibabaCloudKms(endpoint: 'kms.internal.example.com',"
                        + " secrets: [[secretType: 'Secret', name: 'any-secret', envVariable: 'ANY_SECRET']]) {\n"
                        + "  echo 'BODY_MUST_NOT_RUN'\n"
                        + "}\n",
                true));

        WorkflowRun build = jenkins.buildAndAssertStatus(Result.FAILURE, job);

        String log = JenkinsRule.getLog(build);
        assertTrue("the rejection must name the endpoint: " + log, log.contains("kms.internal.example.com"));
        assertTrue("and the whitelist it was measured against: " + log, log.contains("*.aliyuncs.com"));
        assertFalse("the body must not run when binding failed", log.contains("BODY_MUST_NOT_RUN"));
    }

    @Test
    public void anOmittedEnvironmentVariableFailsBeforeAnyConnection() throws Exception {
        assertRejectedBeforeAnyConnection(
                "kms-step-no-variable",
                "secrets: [[secretType: 'Secret', name: 'any-secret']]",
                "secrets[0] (any-secret) has no environment variable");
    }

    @Test
    public void anEmptyEnvironmentVariableFailsBeforeAnyConnection() throws Exception {
        assertRejectedBeforeAnyConnection(
                "kms-step-blank-variable",
                "secrets: [[secretType: 'Secret', name: 'any-secret', envVariable: '   ']]",
                "secrets[0] (any-secret) has no environment variable");
    }

    @Test
    public void anEmptySecretNameFailsBeforeAnyConnection() throws Exception {
        assertRejectedBeforeAnyConnection(
                "kms-step-blank-name",
                "secrets: [[secretType: 'Secret', name: '', envVariable: 'ANY_SECRET']]",
                "secrets[0] has no secret name");
    }

    /**
     * {@code kms.invalid} is reserved to never resolve, so a log that names it is proof a connection was
     * attempted. Nothing here needs a working endpoint: the subject is that an entry which cannot be
     * bound is refused before one is ever used, rather than after its plaintext has been fetched.
     */
    private void assertRejectedBeforeAnyConnection(String jobName, String secrets, String rejection)
            throws Exception {
        KmsGlobalConfiguration.get().setEndpoint("kms.invalid");

        WorkflowJob job = jenkins.createProject(WorkflowJob.class, jobName);
        job.setDefinition(new CpsFlowDefinition(
                "withAlibabaCloudKms(" + secrets + ") {\n" + "  echo 'BODY_MUST_NOT_RUN'\n" + "}\n", true));

        WorkflowRun build = jenkins.buildAndAssertStatus(Result.FAILURE, job);

        String log = JenkinsRule.getLog(build);
        assertTrue("the rejection must name the offending entry: " + log, log.contains(rejection));
        assertFalse("the body must not run when binding failed", log.contains("BODY_MUST_NOT_RUN"));
        assertFalse("no endpoint may be contacted for a configuration error: " + log, log.contains("kms.invalid"));
    }
}
