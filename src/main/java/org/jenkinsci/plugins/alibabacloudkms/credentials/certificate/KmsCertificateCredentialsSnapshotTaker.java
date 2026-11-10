package org.jenkinsci.plugins.alibabacloudkms.credentials.certificate;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import hudson.Extension;
import org.jenkinsci.plugins.alibabacloudkms.credentials.Snapshot;

@Extension
@SuppressWarnings("unused")
public class KmsCertificateCredentialsSnapshotTaker extends CredentialsSnapshotTaker<KmsCertificateCredentials> {

    @Override
    public Class<KmsCertificateCredentials> type() {
        return KmsCertificateCredentials.class;
    }

    @Override
    public KmsCertificateCredentials snapshot(KmsCertificateCredentials credential) {
        return new KmsCertificateCredentials(
                credential.getScope(),
                credential.getId(),
                credential.getDescription(),
                new Snapshot<>(credential.getPassword()),
                new Snapshot<>(credential.getKeyStoreSecret()));
    }
}
