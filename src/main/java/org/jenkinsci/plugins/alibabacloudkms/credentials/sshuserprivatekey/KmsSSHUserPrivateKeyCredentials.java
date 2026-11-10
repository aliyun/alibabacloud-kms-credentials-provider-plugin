package org.jenkinsci.plugins.alibabacloudkms.credentials.sshuserprivatekey;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.Messages;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.alibabacloudkms.KmsCredentialsProvider;
import org.jvnet.localizer.ResourceBundleHolder;

public class KmsSSHUserPrivateKeyCredentials extends BaseStandardCredentials implements SSHUserPrivateKey {

    private final String username;
    private final Supplier<Secret> value;
    private final Supplier<Secret> passphrase;

    public KmsSSHUserPrivateKeyCredentials(
            CredentialsScope scope,
            String id,
            String description,
            String username,
            Supplier<Secret> passphrase,
            Supplier<Secret> privateKey) {
        super(scope, id, description);
        this.username = StringUtils.defaultString(username);
        this.passphrase = passphrase;
        this.value = privateKey;
    }

    public Secret getSecretValue() {
        return value.get();
    }

    @NonNull
    @Override
    public String getPrivateKey() {
        String key = Secret.toString(value.get());

        return appendNewLineIfMissing(key);
    }

    @Override
    public Secret getPassphrase() {
        return passphrase.get();
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        String privateKeys = Secret.toString(value.get());
        List<String> keys = StringUtils.isBlank(privateKeys)
                ? Collections.emptyList()
                : Arrays.asList(StringUtils.split(privateKeys, "\f"));

        return keys.stream()
                .map(KmsSSHUserPrivateKeyCredentials::appendNewLineIfMissing)
                .collect(Collectors.toList());
    }

    private static String appendNewLineIfMissing(String key) {
        return key.endsWith("\n") ? key : key + "\n";
    }

    @NonNull
    @Override
    public String getUsername() {
        return username;
    }

    @Extension
    @SuppressWarnings("unused")
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("BasicSSHUserPrivateKey.DisplayName");
        }

        @Override
        public String getIconClassName() {
            return "icon-ssh-credentials-ssh-key";
        }

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return provider instanceof KmsCredentialsProvider;
        }
    }
}
