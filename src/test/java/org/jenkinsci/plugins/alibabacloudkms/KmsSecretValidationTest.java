package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import hudson.util.FormValidation;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * The step reads a secret by name and binds the result under a name of the user's choosing, so a blank
 * value is only cheap to fix while it is still being typed.
 */
public class KmsSecretValidationTest {

    @Rule public JenkinsRule j = new JenkinsRule();

    /** Assigned in {@code setUp} rather than inline: a {@code Descriptor} needs the rule's Jenkins first. */
    private KmsSecret.DescriptorImpl descriptor;

    @Before
    public void setUp() {
        descriptor = new KmsSecret.DescriptorImpl();
    }

    @Test
    public void rejectsABlankEnvironmentVariable() {
        assertError(descriptor.doCheckEnvVariable(null, ""));
        assertError(descriptor.doCheckEnvVariable(null, "   "));
        assertError(descriptor.doCheckEnvVariable(null, null));
    }

    @Test
    public void acceptsAnyNonBlankEnvironmentVariable() {
        // Blank is the only thing refused. Whether a name is one a given shell can read unquoted is the
        // agent's business, and these are names callers already depend on.
        assertOk(descriptor.doCheckEnvVariable(null, "DB_PASSWORD"));
        assertOk(descriptor.doCheckEnvVariable(null, "DB-PASSWORD"));
        assertOk(descriptor.doCheckEnvVariable(null, "1PASSWORD"));
        assertOk(descriptor.doCheckEnvVariable(null, "DB PASSWORD"));
        assertOk(descriptor.doCheckEnvVariable(null, "  DB_PASSWORD  "));
    }

    @Test
    public void rejectsABlankSecretName() {
        assertError(descriptor.doCheckName(null, ""));
        assertError(descriptor.doCheckName(null, "   "));
        assertError(descriptor.doCheckName(null, null));
        assertOk(descriptor.doCheckName(null, "team/db/password"));
    }

    @Test
    public void theConstructorStoresWhatTheCheckValidates() {
        KmsSecret trimmed = new KmsSecret(KmsSecret.TYPE_SECRET, "  db/password  ", "  DB_PASSWORD  ");
        assertEquals("db/password", trimmed.getName());
        assertEquals("DB_PASSWORD", trimmed.getEnvVariable());

        KmsSecret blank = new KmsSecret(KmsSecret.TYPE_FILE, "  ", "");
        assertNull("a blank name must not survive as an empty string", blank.getName());
        assertNull(blank.getEnvVariable());
    }

    private static void assertOk(FormValidation validation) {
        assertEquals(FormValidation.Kind.OK, validation.kind);
    }

    private static void assertError(FormValidation validation) {
        assertEquals(FormValidation.Kind.ERROR, validation.kind);
    }
}
