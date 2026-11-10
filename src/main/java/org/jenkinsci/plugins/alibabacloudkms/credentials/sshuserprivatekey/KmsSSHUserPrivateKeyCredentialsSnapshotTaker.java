package org.jenkinsci.plugins.alibabacloudkms.credentials.sshuserprivatekey;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import org.jenkinsci.plugins.alibabacloudkms.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class KmsSSHUserPrivateKeyCredentialsSnapshotTaker
        extends CredentialsSnapshotTaker<KmsSSHUserPrivateKeyCredentials> {

    @Override
    public Class<KmsSSHUserPrivateKeyCredentials> type() {
        return KmsSSHUserPrivateKeyCredentials.class;
    }

    @Override
    public KmsSSHUserPrivateKeyCredentials snapshot(KmsSSHUserPrivateKeyCredentials credential) {
        return new KmsSSHUserPrivateKeyCredentials(
                credential.getScope(),
                credential.getId(),
                credential.getDescription(),
                credential.getUsername(),
                new Snapshot<>(credential.getPassphrase()),
                new Snapshot<>(credential.getSecretValue()));
    }
}
