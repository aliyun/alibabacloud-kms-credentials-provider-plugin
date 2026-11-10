package org.jenkinsci.plugins.alibabacloudkms;

import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.Run;
import hudson.util.Secret;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Collection;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Masks the values bound by {@link KmsStep} in the build log.
 *
 * <p>The aggregate pattern is held as a {@link Secret} rather than a {@link Pattern} because this
 * filter travels in the step's serialized program state. {@code Pattern} is itself serializable and
 * writes its expression out verbatim, so a bare field would persist every bound secret in plaintext
 * inside {@code builds/<n>/program.dat} on the controller.</p>
 */
public class MaskingConsoleLogFilter extends ConsoleLogFilter implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Comparator<String> BY_LENGTH_DESCENDING =
            Comparator.comparingInt(String::length).reversed().thenComparing(String::compareTo);

    private final String charsetName;
    private final Secret pattern;

    public MaskingConsoleLogFilter(String charsetName, Collection<String> secrets) {
        this.charsetName = charsetName;
        this.pattern = Secret.fromString(aggregateSecretPattern(secrets).pattern());
    }

    /**
     * Builds a single alternation matching any of the bound secret values. credentials-binding's own
     * {@code SecretPatterns} is not reachable — that plugin is a test-only dependency here, so a
     * controller can use the credentials provider without installing Pipeline — so the aggregate is
     * assembled here. Longer values are placed first so that a value which is a substring of another is
     * masked as the longer one, and each is {@link Pattern#quote quoted} so a value's own regex
     * metacharacters cannot leak structure into the log. Only the literal value is masked; the
     * shell-quoting variants credentials-binding adds are likewise not reproduced.
     */
    private static Pattern aggregateSecretPattern(Collection<String> secrets) {
        String expression = secrets.stream()
                .filter(secret -> !secret.isEmpty())
                .sorted(BY_LENGTH_DESCENDING)
                .distinct()
                .map(Pattern::quote)
                .collect(Collectors.joining("|"));
        return Pattern.compile(expression);
    }

    @Override
    public OutputStream decorateLogger(Run run, OutputStream logger) {
        // Compile once here rather than per line: the aggregate pattern is stable for the whole log,
        // and recompiling it as the log streams would be wasteful on a busy build.
        return new MaskingOutputStream(logger, Pattern.compile(pattern.getPlainText()), charsetName);
    }

    /**
     * Line-buffering masker over the build log. credentials-binding's own {@code SecretPatterns} is not
     * reachable at runtime — that plugin is a test-only dependency here — so the masking is done directly
     * on the {@link LineTransformationOutputStream} base, which buffers by line so a secret split across
     * write boundaries is still caught.
     */
    private static final class MaskingOutputStream extends LineTransformationOutputStream {

        private final OutputStream out;
        private final Pattern pattern;
        private final String charsetName;

        MaskingOutputStream(OutputStream out, Pattern pattern, String charsetName) {
            this.out = out;
            this.pattern = pattern;
            this.charsetName = charsetName;
        }

        @Override
        protected void eol(byte[] b, int len) throws IOException {
            if (pattern.pattern().isEmpty()) {
                // No secrets bound: avoid the byte -> char -> byte round trip entirely.
                out.write(b, 0, len);
                return;
            }
            Matcher m = pattern.matcher(new String(b, 0, len, charsetName));
            if (m.find()) {
                out.write(m.replaceAll("****").getBytes(charsetName));
            } else {
                out.write(b, 0, len);
            }
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            super.close();
            out.close();
        }
    }
}
