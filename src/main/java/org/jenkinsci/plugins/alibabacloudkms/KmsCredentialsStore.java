package org.jenkinsci.plugins.alibabacloudkms;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.CredentialsStoreAction;
import com.cloudbees.plugins.credentials.domains.Domain;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.ModelObject;
import hudson.security.ACL;
import hudson.security.Permission;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import org.jenkins.ui.icon.IconSpec;
import org.acegisecurity.Authentication;

/**
 * Read-only credentials store backed by Alibaba Cloud KMS. Jenkins can list and use credentials but
 * may not add, remove or update them here — secrets are managed in KMS itself.
 */
public class KmsCredentialsStore extends CredentialsStore implements IconSpec {

    private final KmsCredentialsProvider provider;
    private final KmsCredentialsStoreAction action = new KmsCredentialsStoreAction(this);

    public KmsCredentialsStore(KmsCredentialsProvider provider) {
        super(KmsCredentialsProvider.class);
        this.provider = provider;
    }

    @Override
    public String getIconClassName() {
        return "symbol-kms plugin-alibabacloud-kms-credentials-provider";
    }

    @NonNull
    @Override
    public ModelObject getContext() {
        return Jenkins.get();
    }

    @Override
    public boolean hasPermission(@NonNull Authentication authentication, @NonNull Permission permission) {
        return CredentialsProvider.VIEW.equals(permission)
                && Jenkins.get().getACL().hasPermission(authentication, permission);
    }

    @NonNull
    @Override
    public List<Credentials> getCredentials(@NonNull Domain domain) {
        if (Domain.global().equals(domain) && Jenkins.get().hasPermission(CredentialsProvider.VIEW)) {
            return provider.getCredentials(
                    Credentials.class, Jenkins.get(), ACL.SYSTEM, Collections.emptyList());
        }
        return Collections.emptyList();
    }

    @Override
    public boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials) {
        throw new UnsupportedOperationException("Jenkins may not add credentials to Alibaba Cloud KMS");
    }

    @Override
    public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) {
        throw new UnsupportedOperationException("Jenkins may not remove credentials in Alibaba Cloud KMS");
    }

    @Override
    public boolean updateCredentials(
            @NonNull Domain domain, @NonNull Credentials credentials, @NonNull Credentials credentials1) {
        throw new UnsupportedOperationException("Jenkins may not update credentials in Alibaba Cloud KMS");
    }

    @Nullable
    @Override
    public CredentialsStoreAction getStoreAction() {
        return action;
    }

    public static final class KmsCredentialsStoreAction extends CredentialsStoreAction {

        private final KmsCredentialsStore store;

        private KmsCredentialsStoreAction(KmsCredentialsStore store) {
            this.store = store;
        }

        @NonNull
        @Override
        public CredentialsStore getStore() {
            return store;
        }

        @Override
        public String getDisplayName() {
            return "Alibaba Cloud KMS";
        }
    }
}
