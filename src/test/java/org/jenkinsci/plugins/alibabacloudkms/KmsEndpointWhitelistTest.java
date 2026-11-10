package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Covers {@link KmsEndpointWhitelist}, which bounds the endpoint a job may name in
 * {@code withAlibabaCloudKms}. No Jenkins instance is needed: the whitelist is passed in rather than read
 * from the global configuration.
 */
public class KmsEndpointWhitelistTest {

    @Test
    public void theDefaultWhitelistAcceptsSubdomainsOfAliyuncsAndNothingElse() {
        // A blank whitelist means "not configured", so the default *.aliyuncs.com applies.
        allow("kms.cn-hangzhou.aliyuncs.com", null);
        allow("kms-vpc.cn-shanghai.aliyuncs.com", "   ");

        reject("aliyuncs.com", null);
        reject("evilaliyuncs.com", null);
        reject("aliyuncs.com.evil.net", null);
        reject("kms.cn-hangzhou.aliyuncs.com.evil.net", null);
    }

    @Test
    public void matchingIgnoresCaseAndAllowsAPort() {
        allow("KMS.CN-HANGZHOU.ALIYUNCS.COM", "*.ALIYUNCS.COM");
        allow("kms.cn-hangzhou.aliyuncs.com:8443", null);
    }

    @Test
    public void aCommaSeparatedWhitelistAllowsSeveralPatterns() {
        String whitelist = "*.aliyuncs.com, kms.internal.example.com ,*.corp.example.net";

        allow("kms.cn-hangzhou.aliyuncs.com", whitelist);
        allow("kms.internal.example.com", whitelist);
        allow("kms.lab.corp.example.net", whitelist);

        reject("kms.example.org", whitelist);
    }

    @Test
    public void anExactHostNameIsStricterThanAPattern() {
        String whitelist = "kms.cn-hangzhou.aliyuncs.com";

        allow("kms.cn-hangzhou.aliyuncs.com", whitelist);

        reject("kms.cn-shanghai.aliyuncs.com", whitelist);
        reject("sub.kms.cn-hangzhou.aliyuncs.com", whitelist);
    }

    @Test
    public void aRejectedEndpointIsReportedWithTheWhitelistItWasMeasuredAgainst() {
        KmsPluginException e = assertThrows(
                KmsPluginException.class,
                () -> KmsEndpointWhitelist.requireAllowed("kms.example.org", "*.aliyuncs.com, *.example.net"));
        assertTrue(e.getMessage(), e.getMessage().contains("kms.example.org"));
        assertTrue(e.getMessage(), e.getMessage().contains("*.aliyuncs.com, *.example.net"));
    }

    @Test
    public void userinfoIsRefusedHoweverWideTheWhitelistIs() {
        // "*" is how an administrator switches the check off, and it still may not admit this: the SDK
        // builds its request URL as protocol + "://" + endpoint, so the endpoint is parsed as a URI
        // authority and this one connects to localhost while reading like an allowed host.
        allow("anything.at.all", "*");

        reject("kms.cn-hangzhou.aliyuncs.com@localhost:19443", "*");
        reject("@localhost", "*");
    }

    @Test
    public void anEndpointThatIsNotABareHostNameIsRefused() {
        // "https://kms..." parses with "https" as the host, so it matches no pattern written for the real
        // host name; a non-numeric port leaves no host to match at all.
        reject("https://kms.cn-hangzhou.aliyuncs.com", null);
        reject("kms.cn-hangzhou.aliyuncs.com:notaport", "*");
    }

    private static void allow(String endpoint, String whitelist) {
        KmsEndpointWhitelist.requireAllowed(endpoint, whitelist);
    }

    private static void reject(String endpoint, String whitelist) {
        KmsPluginException e = assertThrows(
                endpoint,
                KmsPluginException.class,
                () -> KmsEndpointWhitelist.requireAllowed(endpoint, whitelist));
        assertTrue(e.getMessage(), e.getMessage().contains(endpoint));
    }
}
