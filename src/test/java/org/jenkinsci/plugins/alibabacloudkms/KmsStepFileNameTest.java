package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import org.junit.Test;

/**
 * The prefix handed to {@code FilePath.createTempFile} reaches a {@code File} binding, so a KMS secret
 * name has to survive the trip. KMS does not restrict names to filesystem-safe characters.
 */
public class KmsStepFileNameTest {

    @Test
    public void leavesFilesystemSafeNamesAlone() {
        assertEquals("my-key_v1.0", KmsStep.ExecutionImpl.escapeFileNameComponent("my-key_v1.0"));
    }

    @Test
    public void escapesTheSeparatorsThatWouldSplitThePrefixIntoAPath() {
        assertEquals("team%2Fdb%2Fpassword", KmsStep.ExecutionImpl.escapeFileNameComponent("team/db/password"));
        assertEquals("a%5Cb", KmsStep.ExecutionImpl.escapeFileNameComponent("a\\b"));
    }

    @Test
    public void escapesTheCharactersWindowsReserves() {
        String escaped = KmsStep.ExecutionImpl.escapeFileNameComponent("<a>:\"b\"|c?d*e");
        for (char reserved : new char[] {'<', '>', ':', '"', '\\', '|', '?', '*'}) {
            assertFalse(escaped + " still contains " + reserved, escaped.indexOf(reserved) >= 0);
        }
    }

    @Test
    public void escapesNonAsciiOverUtf8() {
        assertEquals("%E6%95%B0%E6%8D%AE", KmsStep.ExecutionImpl.escapeFileNameComponent("数据"));
    }

    @Test
    public void escapesTheEscapeCharacterSoTwoNamesCannotShareAPrefix() {
        assertNotEquals(
                KmsStep.ExecutionImpl.escapeFileNameComponent("a/b"),
                KmsStep.ExecutionImpl.escapeFileNameComponent("a%2Fb"));
    }

    @Test
    public void theBuiltPrefixSurvivesTheFileBindingInsideOneDirectory() throws Exception {
        File dir = Files.createTempDirectory("kms-filename-test").toFile().getCanonicalFile();
        try {
            for (String name : new String[] {"team/db/password", "a\\b", "<x>:\"y\"|z?w*v", "数据", "plain-name"}) {
                File created = File.createTempFile(
                                "kms-" + KmsStep.ExecutionImpl.escapeFileNameComponent(name) + "-", ".dat", dir)
                        .getCanonicalFile();
                assertEquals("'" + name + "' must not escape the secret directory", dir, created.getParentFile());
                assertTrue(created.delete());
            }
        } finally {
            assertTrue(dir.delete());
        }
    }
}
