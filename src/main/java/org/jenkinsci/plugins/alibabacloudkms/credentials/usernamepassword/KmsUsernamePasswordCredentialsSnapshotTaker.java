package org.jenkinsci.plugins.alibabacloudkms.credentials.usernamepassword;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import org.jenkinsci.plugins.alibabacloudkms.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class KmsUsernamePasswordCredentialsSnapshotTaker
        extends CredentialsSnapshotTaker<KmsUsernamePasswordCredentials> {

    @Override
    public Class<KmsUsernamePasswordCredentials> type() {
        return KmsUsernamePasswordCredentials.class;
    }

    @Override
    public KmsUsernamePasswordCredentials snapshot(KmsUsernamePasswordCredentials credential) {
        // Both halves are resolved here, so a snapshot carries no KMS dependency into a build agent.
        return new KmsUsernamePasswordCredentials(
                credential.getScope(),
                credential.getId(),
                new Snapshot<>(credential.getUsername()),
                credential.getDescription(),
                new Snapshot<>(credential.getPassword()));
    }
}
