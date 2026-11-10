package org.jenkinsci.plugins.alibabacloudkms;

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.Serializable;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * A single Alibaba Cloud KMS secret to bind into a build environment.
 */
public class KmsSecret extends AbstractDescribableImpl<KmsSecret> implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final String TYPE_SECRET = "Secret";
    public static final String TYPE_FILE = "File";

    private final String secretType;
    private final String name;
    private final String envVariable;
    private String version;

    // structs leaves a missing non-primitive constructor argument as null rather than failing, so a
    // pipeline that simply omits envVariable gets here; normalizing collapses that and the empty-field
    // route from the UI into the one value the execution-time check has to recognize.
    @DataBoundConstructor
    public KmsSecret(String secretType, String name, String envVariable) {
        this.secretType = secretType;
        this.name = Util.fixEmptyAndTrim(name);
        this.envVariable = Util.fixEmptyAndTrim(envVariable);
    }

    public String getSecretType() {
        return secretType;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    @DataBoundSetter
    public void setVersion(String version) {
        this.version = Util.fixEmpty(version);
    }

    public String getEnvVariable() {
        return envVariable;
    }

    /**
     * {@code true} when the secret value is written to a workspace file and the environment variable
     * holds the file path instead of the value itself.
     */
    public boolean isFile() {
        return TYPE_FILE.equals(secretType);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<KmsSecret> {
        @Override
        public String getDisplayName() {
            return "Environment variable, name/version pair for an Alibaba Cloud KMS secret";
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillSecretTypeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(TYPE_SECRET, TYPE_SECRET);
            items.add(TYPE_FILE, TYPE_FILE);
            return items;
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckName(@AncestorInPath Item context, @QueryParameter String value) {
            if (!mayValidate(context)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(value)) {
                return FormValidation.error("Secret name is required");
            }
            return FormValidation.ok();
        }

        /**
         * Blank is the only thing rejected: which characters make up a usable environment variable is
         * the agent's shell's business, not this form's, and refusing a name a caller already relies on
         * would be a behaviour change rather than a validation.
         */
        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckEnvVariable(@AncestorInPath Item context, @QueryParameter String value) {
            if (!mayValidate(context)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(value)) {
                return FormValidation.error("Environment variable is required");
            }
            return FormValidation.ok();
        }

        /**
         * Degrades to no check rather than throwing: form validation is a convenience over a step that
         * still runs the same way it always did, so a caller without configure permission must not be
         * blocked from saving the job.
         */
        private static boolean mayValidate(Item context) {
            return context == null
                    ? Jenkins.get().hasPermission(Jenkins.ADMINISTER)
                    : context.hasPermission(Item.CONFIGURE);
        }
    }
}
