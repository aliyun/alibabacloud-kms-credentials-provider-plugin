package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.EnvVars;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.support.pickles.serialization.RiverWriter;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * The expander is part of a step's serialized program state, which Jenkins writes to
 * {@code builds/<n>/program.dat} on the controller and keeps for the life of the build record.
 */
public class KmsEnvironmentExpanderTest {

    @Rule public JenkinsRule jenkins = new JenkinsRule();

    private static final String SECRET_VALUE = "kms-plaintext-that-must-not-be-persisted";
    private static final String FILE_PATH = "/home/jenkins/workspace/job@tmp/kms-file-1234.dat";

    @Test
    public void programStateCarriesNoSecretPlaintext() throws Exception {
        // program.dat is written by workflow-support's RiverWriter rather than by plain Java
        // serialization, so this asserts against the mechanism that actually persists the expander.
        assertTrue(
                "control: the marshalling harness must be able to see a secret held in a bare String field",
                marshal(new RawEnvironmentHolder(secrets())).contains(SECRET_VALUE));

        String persisted = marshal(new KmsEnvironmentExpander(secrets(), publicValues()));

        assertFalse(
                "the persisted expander must not carry the secret in plaintext", persisted.contains(SECRET_VALUE));
        assertTrue(
                "a workspace path is not secret material and must stay readable, or the build cannot find the file",
                persisted.contains(FILE_PATH));
    }

    @Test
    public void stillExpandsAfterARoundTrip() throws Exception {
        KmsEnvironmentExpander restored =
                (KmsEnvironmentExpander) roundTrip(new KmsEnvironmentExpander(secrets(), publicValues()));

        EnvVars env = new EnvVars();
        restored.expand(env);

        assertEquals(SECRET_VALUE, env.get("DB_PASSWORD"));
        assertEquals(FILE_PATH, env.get("FILE_VALUE"));
        assertEquals("expanding must add exactly the bound variables", 2, env.size());
    }

    private static Map<String, String> secrets() {
        Map<String, String> secrets = new LinkedHashMap<>();
        secrets.put("DB_PASSWORD", SECRET_VALUE);
        return secrets;
    }

    private static Map<String, String> publicValues() {
        Map<String, String> publicValues = new LinkedHashMap<>();
        publicValues.put("FILE_VALUE", FILE_PATH);
        return publicValues;
    }

    /** Stands in for the pre-fix expander: the same environment held in a plain String map. */
    private static final class RawEnvironmentHolder implements Serializable {

        private static final long serialVersionUID = 1L;

        private final Map<String, String> secrets;

        RawEnvironmentHolder(Map<String, String> secrets) {
            this.secrets = secrets;
        }
    }

    private static String marshal(Serializable object) throws Exception {
        File file = File.createTempFile("program", ".dat");
        try {
            try (RiverWriter writer = new RiverWriter(file, FlowExecutionOwner.dummyOwner())) {
                writer.writeObject(object);
            }
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.ISO_8859_1);
        } finally {
            Files.deleteIfExists(file.toPath());
        }
    }

    private static Object roundTrip(Serializable object) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(object);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return in.readObject();
        }
    }
}
