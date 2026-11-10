package org.jenkinsci.plugins.alibabacloudkms.credentials.string;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import org.jenkinsci.plugins.alibabacloudkms.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class KmsStringCredentialsSnapshotTaker extends CredentialsSnapshotTaker<KmsStringCredentials> {

    @Override
    public Class<KmsStringCredentials> type() {
        return KmsStringCredentials.class;
    }

    @Override
    public KmsStringCredentials snapshot(KmsStringCredentials credential) {
        return new KmsStringCredentials(
                credential.getScope(),
                credential.getId(),
                credential.getDescription(),
                new Snapshot<>(credential.getSecret()));
    }
}
