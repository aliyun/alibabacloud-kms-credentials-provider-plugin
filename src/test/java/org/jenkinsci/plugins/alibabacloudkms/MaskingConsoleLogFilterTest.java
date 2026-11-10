package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.model.Run;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.support.pickles.serialization.RiverWriter;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * The masking filter is part of a step's serialized program state, which Jenkins writes to
 * {@code builds/<n>/program.dat} on the controller and keeps for the life of the build record.
 */
public class MaskingConsoleLogFilterTest {

    @Rule public JenkinsRule jenkins = new JenkinsRule();

    private static final String SECRET = "kms-plaintext-that-must-not-be-persisted";

    @Test
    public void programStateCarriesNoSecretPlaintext() throws Exception {
        // program.dat is written by workflow-support's RiverWriter rather than by plain Java
        // serialization, so this asserts against the mechanism that actually persists the filter.
        assertTrue(
                "control: the marshalling harness must be able to see a secret held in a bare Pattern field",
                marshal(new RawPatternHolder(Collections.singletonList(SECRET))).contains(SECRET));
        assertFalse(
                "the persisted masking filter must not carry the secret in plaintext",
                marshal(new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Collections.singletonList(SECRET)))
                        .contains(SECRET));
    }

    @Test
    public void stillMasksAfterARoundTrip() throws Exception {
        MaskingConsoleLogFilter filter =
                new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Collections.singletonList(SECRET));

        MaskingConsoleLogFilter restored = (MaskingConsoleLogFilter) roundTrip(filter);

        assertEquals("value=****\n", mask(restored, StandardCharsets.UTF_8, "value=" + SECRET));
    }

    @Test
    public void masksWithTheCharsetItWasGiven() throws Exception {
        Charset gbk = Charset.forName("GBK");
        String secret = "密钥-value-9f3";
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(gbk.name(), Collections.singletonList(secret));

        String masked = mask(filter, gbk, "口令=" + secret);

        assertFalse("a non-ASCII secret must still be masked", masked.contains(secret));
        assertTrue(
                "the surrounding log line must survive in the build's own charset: " + masked,
                masked.contains("口令=****"));
    }

    @Test
    public void leavesLogUntouchedWhenNothingIsBound() throws Exception {
        MaskingConsoleLogFilter filter =
                new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Collections.emptyList());

        assertEquals("nothing to mask here\n", mask(filter, StandardCharsets.UTF_8, "nothing to mask here"));
    }

    /** Stands in for the pre-fix filter: the same aggregate pattern held in a plain field. */
    private static final class RawPatternHolder implements Serializable {

        private static final long serialVersionUID = 1L;

        private final Pattern pattern;

        RawPatternHolder(Collection<String> secrets) {
            this.pattern = Pattern.compile(
                    secrets.stream().map(Pattern::quote).collect(java.util.stream.Collectors.joining("|")));
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

    private static String mask(MaskingConsoleLogFilter filter, Charset charset, String line) throws Exception {
        Run<?, ?> noRun = null;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (OutputStream masked = filter.decorateLogger(noRun, sink)) {
            masked.write(line.getBytes(charset));
            masked.write('\n');
        }
        return sink.toString(charset.name());
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
