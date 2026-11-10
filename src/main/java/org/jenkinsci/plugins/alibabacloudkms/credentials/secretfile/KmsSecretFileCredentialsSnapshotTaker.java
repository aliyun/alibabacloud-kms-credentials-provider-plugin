package org.jenkinsci.plugins.alibabacloudkms.credentials.secretfile;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import org.jenkinsci.plugins.alibabacloudkms.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class KmsSecretFileCredentialsSnapshotTaker extends CredentialsSnapshotTaker<KmsSecretFileCredentials> {

    @Override
    public Class<KmsSecretFileCredentials> type() {
        return KmsSecretFileCredentials.class;
    }

    @Override
    public KmsSecretFileCredentials snapshot(KmsSecretFileCredentials credential) {
        return new KmsSecretFileCredentials(
                credential.getScope(),
                credential.getId(),
                credential.getDescription(),
                credential.getFileName(),
                new Snapshot<>(credential.getSecretBytes()));
    }
}
