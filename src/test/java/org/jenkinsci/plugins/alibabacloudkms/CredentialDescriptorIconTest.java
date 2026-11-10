package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;

import org.jenkinsci.plugins.alibabacloudkms.credentials.certificate.KmsCertificateCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.secretfile.KmsSecretFileCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.sshuserprivatekey.KmsSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.string.KmsStringCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.usernamepassword.KmsUsernamePasswordCredentials;
import org.junit.Test;

public class CredentialDescriptorIconTest {

    @Test
    public void matchesNativeCredentialTypeIcons() {
        // Each value is the icon the corresponding native descriptor reports on this core baseline
        // (credentials 2.3.11 / plain-credentials 1.7 / ssh-credentials 1.17.4). Secret text and
        // secret file both fall back to the generic CredentialsDescriptor default; the symbol-* icon
        // names used on newer cores are not registered here and would render blank.
        assertEquals(
                "icon-credentials-credential",
                new KmsStringCredentials.DescriptorImpl().getIconClassName());
        assertEquals(
                "icon-credentials-credential",
                new KmsSecretFileCredentials.DescriptorImpl().getIconClassName());
        assertEquals(
                "icon-credentials-userpass",
                new KmsUsernamePasswordCredentials.DescriptorImpl().getIconClassName());
        assertEquals(
                "icon-ssh-credentials-ssh-key",
                new KmsSSHUserPrivateKeyCredentials.DescriptorImpl().getIconClassName());
        assertEquals(
                "icon-credentials-certificate",
                new KmsCertificateCredentials.DescriptorImpl().getIconClassName());
    }
}
