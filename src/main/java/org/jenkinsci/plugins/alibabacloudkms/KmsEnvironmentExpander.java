package org.jenkinsci.plugins.alibabacloudkms;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.util.Secret;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;

public class KmsEnvironmentExpander extends EnvironmentExpander {

    private static final long serialVersionUID = 1L;

    /**
     * Held as {@link Secret} rather than {@link String} because this expander travels in the step's
     * serialized program state: a plain field would persist every bound value in plaintext inside
     * {@code builds/<n>/program.dat} on the controller.
     */
    private final Map<String, Secret> secrets = new LinkedHashMap<>();

    /**
     * Variables holding a workspace path to a file secret rather than secret material. A path is not
     * sensitive, and masking it would redact the location the build needs to read the file from.
     */
    private final Map<String, String> publicValues;

    KmsEnvironmentExpander(Map<String, String> secrets, Map<String, String> publicValues) {
        secrets.forEach((name, value) -> this.secrets.put(name, Secret.fromString(value)));
        this.publicValues = publicValues;
    }

    /**
     * Injects the bound values into the build environment. The step masks them in the console log through
     * its own {@link MaskingConsoleLogFilter}; the {@code EnvironmentExpander.getSensitiveVariables} hook
     * that would additionally flag them to the workflow engine does not exist on this plugin's core floor
     * and so is not overridden here.
     */
    @Override
    public void expand(@NonNull EnvVars env) throws IOException, InterruptedException {
        secrets.forEach((name, value) -> env.override(name, value.getPlainText()));
        env.overrideAll(publicValues);
    }
}
