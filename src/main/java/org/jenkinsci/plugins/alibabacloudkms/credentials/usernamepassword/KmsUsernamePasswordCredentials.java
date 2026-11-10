package org.jenkinsci.plugins.alibabacloudkms.credentials.usernamepassword;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.Messages;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.jenkinsci.plugins.alibabacloudkms.KmsCredentialsProvider;
import org.jvnet.localizer.ResourceBundleHolder;

public class KmsUsernamePasswordCredentials extends BaseStandardCredentials
        implements StandardUsernamePasswordCredentials {

    private final Supplier<Secret> password;
    private final Supplier<String> username;

    public KmsUsernamePasswordCredentials(
            CredentialsScope scope,
            String id,
            Supplier<String> username,
            String description,
            Supplier<Secret> password) {
        super(scope, id, description);
        this.password = password;
        this.username = username;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return password.get();
    }

    /**
     * A managed secret whose value cannot be read caches the failure and rethrows it here. That is fine
     * for a binding — {@link #getPassword()} throws the same failure and fails the build loudly — but the
     * username is also resolved while Jenkins renders a credential picker, which is outside the
     * provider's try/catch, so letting it escape would break the whole list rather than one entry. The
     * read failure is already logged by the retriever; render an empty username instead.
     */
    @NonNull
    @Override
    public String getUsername() {
        try {
            return Util.fixNull(username.get());
        } catch (RuntimeException | LinkageError e) {
            return "";
        }
    }

    @Extension(ordinal = 1)
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("UsernamePasswordCredentialsImpl.DisplayName");
        }

        @Override
        public String getIconClassName() {
            return "icon-credentials-userpass";
        }

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return provider instanceof KmsCredentialsProvider;
        }
    }
}
