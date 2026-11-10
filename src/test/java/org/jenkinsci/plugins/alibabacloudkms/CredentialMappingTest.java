package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.ListSecretsRequest;
import com.aliyun.kms20160120.models.ListSecretsResponse;
import com.aliyun.kms20160120.models.ListSecretsResponseBody;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretList;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecret;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecretTags;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecretTagsTag;
import com.aliyun.teaopenapi.models.Config;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.jenkinsci.plugins.alibabacloudkms.credentials.certificate.KmsCertificateCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.secretfile.KmsSecretFileCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.sshuserprivatekey.KmsSSHUserPrivateKeyCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.string.KmsStringCredentials;
import org.jenkinsci.plugins.alibabacloudkms.credentials.usernamepassword.KmsUsernamePasswordCredentials;
import org.junit.Test;

/**
 * Covers the tag-driven mapping from a KMS secret to a concrete Jenkins credential type. Only the
 * listing call is exercised: every credential built here reads its value lazily, so no
 * {@code GetSecretValue} is issued and no real KMS endpoint is needed.
 */
public class CredentialMappingTest {

    private static final String TYPE = "jenkins:credentials:type";
    private static final String ID = "jenkins:credentials:id";
    private static final String SCOPE = "jenkins:credentials:scope";
    private static final String USERNAME = "jenkins:credentials:username";
    private static final String FILE_NAME = "jenkins:credentials:filename";

    @Test
    public void mapsEachCredentialTypeFromItsTag() throws Exception {
        Map<String, IdCredentials> credentials = map(
                secret("no-tags", Collections.emptyMap()),
                secret("explicit-string", Collections.singletonMap(TYPE, "string")),
                secret("file", Collections.singletonMap(TYPE, "secretFile")),
                secret("named-file", tags(TYPE, "secretFile", FILE_NAME, "id_rsa")),
                secret("username", tags(TYPE, "username", USERNAME, "app-user")),
                secret("ssh", tags(TYPE, "sshUserPrivateKey", USERNAME, "git")),
                secret("certificate", Collections.singletonMap(TYPE, "certificate")));

        assertTrue(credentials.get("no-tags") instanceof KmsStringCredentials);
        assertTrue(credentials.get("explicit-string") instanceof KmsStringCredentials);
        assertTrue(credentials.get("file") instanceof KmsSecretFileCredentials);
        assertTrue(credentials.get("named-file") instanceof KmsSecretFileCredentials);
        assertTrue(credentials.get("username") instanceof KmsUsernamePasswordCredentials);
        assertTrue(credentials.get("ssh") instanceof KmsSSHUserPrivateKeyCredentials);
        assertTrue(credentials.get("certificate") instanceof KmsCertificateCredentials);
    }

    @Test
    public void usernameTagAloneDoesNotSelectTheCredentialType() throws Exception {
        // The username tag only supplies a value to the types that ask for one; it never picks the type.
        // Reading it as a type hint would make a secret that explicitly says `string` but carries a stray
        // username tag indistinguishable from one that never set the type tag at all.
        Map<String, IdCredentials> credentials = map(
                secret("no-type", Collections.singletonMap(USERNAME, "db-user")),
                secret("explicit-string", tags(TYPE, "string", USERNAME, "db-user")));

        assertTrue(credentials.get("no-type") instanceof KmsStringCredentials);
        assertTrue(credentials.get("explicit-string") instanceof KmsStringCredentials);
    }

    @Test
    public void readsFileNameAndUsernameFromTags() throws Exception {
        Map<String, IdCredentials> credentials = map(
                secret("named-file", tags(TYPE, "secretFile", FILE_NAME, "id_rsa")),
                secret("file", Collections.singletonMap(TYPE, "secretFile")),
                secret("ssh", tags(TYPE, "sshUserPrivateKey", USERNAME, "git")));

        assertEquals("id_rsa", ((KmsSecretFileCredentials) credentials.get("named-file")).getFileName());
        // Falls back to the secret name so the projected file is never nameless.
        assertEquals("file.txt", ((KmsSecretFileCredentials) credentials.get("file")).getFileName());
        assertEquals("git", ((KmsSSHUserPrivateKeyCredentials) credentials.get("ssh")).getUsername());
    }

    @Test
    public void appliesIdAndScopeTags() throws Exception {
        Map<String, IdCredentials> credentials = map(
                secret("renamed", Collections.singletonMap(ID, "custom-id")),
                secret("system-scoped", Collections.singletonMap(SCOPE, "SYSTEM")));

        assertNull("the id tag must win over the secret name", credentials.get("renamed"));
        assertTrue(credentials.get("custom-id") instanceof KmsStringCredentials);
        assertEquals(CredentialsScope.GLOBAL, credentials.get("custom-id").getScope());
        assertEquals(CredentialsScope.SYSTEM, credentials.get("system-scoped").getScope());
    }

    @Test
    public void skipsUnmappableAndPendingDeletionSecrets() throws Exception {
        Map<String, IdCredentials> credentials = map(
                secret("unknown-type", Collections.singletonMap(TYPE, "not-a-type")),
                pendingDeletion("going-away", Collections.emptyMap()));

        assertNull("an unknown type tag must not invent a credential", credentials.get("unknown-type"));
        assertNull("a secret scheduled for deletion must not be listed", credentials.get("going-away"));
    }

    @Test
    public void firstSecretWinsWhenTwoClaimTheSameCredentialId() throws Exception {
        // KMS does not constrain tag values, so two secrets can be tagged with the same Jenkins id. The
        // map is keyed on that id, so whichever is mapped last would otherwise silently replace the
        // first and a pipeline would bind the wrong secret without anything failing.
        Map<String, IdCredentials> credentials = map(
                secret("first", tags(TYPE, "secretFile", ID, "shared-id", FILE_NAME, "first.pem")),
                secret("second", tags(TYPE, "secretFile", ID, "shared-id", FILE_NAME, "second.pem")));

        assertEquals(1, credentials.size());
        assertEquals(
                "the first secret in listing order must be the one that survives",
                "first.pem",
                ((KmsSecretFileCredentials) credentials.get("shared-id")).getFileName());
    }

    @Test
    public void discoveryStopsAtThePageCap() throws Exception {
        // totalCount is above the cap, so this is the branch that has to stop the loop rather than the
        // one that runs out of secrets: an unbounded walk would keep a single refresh thread issuing
        // ListSecrets calls for as long as KMS kept answering.
        int totalSecrets = 6_000;
        PagingClient client = new PagingClient(totalSecrets);

        Map<String, IdCredentials> credentials = KmsCredentialsProvider.fetchCredentials(
                "endpoint", "jenkins:credentials", client, KmsCredentialsProvider.newCache(300L), 300L);

        assertEquals(50, client.pages);
        assertEquals(5_000, credentials.size());
    }

    private static Map<String, String> tags(String... keysAndValues) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            tags.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return tags;
    }

    private static Map<String, IdCredentials> map(ListSecretsResponseBodySecretListSecret... secrets) throws Exception {
        return KmsCredentialsProvider.fetchCredentials(
                "endpoint",
                "jenkins:credentials",
                new ListingClient(Arrays.asList(secrets)),
                KmsCredentialsProvider.newCache(300L),
                300L);
    }

    private static ListSecretsResponseBodySecretListSecret secret(String name, Map<String, String> tags) {
        ListSecretsResponseBodySecretListSecret secret = new ListSecretsResponseBodySecretListSecret()
                .setSecretName(name)
                .setSecretType("Generic")
                .setUpdateTime("2026-10-13T00:00:00Z");
        if (!tags.isEmpty()) {
            secret.setTags(new ListSecretsResponseBodySecretListSecretTags()
                    .setTag(tags.entrySet().stream()
                            .map(tag -> new ListSecretsResponseBodySecretListSecretTagsTag()
                                    .setTagKey(tag.getKey())
                                    .setTagValue(tag.getValue()))
                            .collect(Collectors.toList())));
        }
        return secret;
    }

    private static ListSecretsResponseBodySecretListSecret pendingDeletion(String name, Map<String, String> tags) {
        return secret(name, tags).setPlannedDeleteTime("2026-10-20T00:00:00Z");
    }

    private static class ListingClient extends Client {

        private final List<ListSecretsResponseBodySecretListSecret> secrets;

        ListingClient(List<ListSecretsResponseBodySecretListSecret> secrets) throws Exception {
            super(new Config().setEndpoint("http://localhost"));
            this.secrets = secrets;
        }

        @Override
        public ListSecretsResponse listSecrets(ListSecretsRequest request) {
            return new ListSecretsResponse()
                    .setBody(new ListSecretsResponseBody()
                            .setTotalCount(secrets.size())
                            .setSecretList(new ListSecretsResponseBodySecretList().setSecret(secrets)));
        }
    }

    /** Serves a listing far larger than one page, generating each page on demand. */
    private static class PagingClient extends Client {

        private final int totalCount;
        private int pages;

        PagingClient(int totalCount) throws Exception {
            super(new Config().setEndpoint("http://localhost"));
            this.totalCount = totalCount;
        }

        @Override
        public ListSecretsResponse listSecrets(ListSecretsRequest request) {
            pages++;
            int pageSize = request.getPageSize();
            int first = (request.getPageNumber() - 1) * pageSize;
            List<ListSecretsResponseBodySecretListSecret> page = new ArrayList<>();
            for (int i = first; i < Math.min(first + pageSize, totalCount); i++) {
                page.add(secret("secret-" + i, Collections.emptyMap()));
            }
            return new ListSecretsResponse()
                    .setBody(new ListSecretsResponseBody()
                            .setTotalCount(totalCount)
                            .setSecretList(new ListSecretsResponseBodySecretList().setSecret(page)));
        }
    }
}
