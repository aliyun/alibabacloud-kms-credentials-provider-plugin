package org.jenkinsci.plugins.alibabacloudkms;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang3.StringUtils;

/**
 * Decides whether an endpoint named by a job may be contacted.
 *
 * <p>Naming an endpoint is the one part of a KMS call a pipeline author controls with Job/Configure
 * alone, far below Overall/Administer. Left unbounded, that lets a job make the controller open a
 * connection to a host of the author's choosing, signed with the controller's own Alibaba Cloud
 * identity, and — because tea-util reflects the whole response body into the exception that reaches the
 * build log — read back whatever answers. The signature is bound to the host, so no credential is
 * disclosed by this.</p>
 *
 * <p>Endpoints an administrator configured are not checked: they arrive through the Overall/Administer
 * gated system configuration, an environment variable or a system property, so whoever set them was
 * already trusted with where the controller talks to.</p>
 */
final class KmsEndpointWhitelist {

    private KmsEndpointWhitelist() {}

    /** Throws unless the host {@code endpoint} resolves to is covered by {@code whitelist}. */
    static void requireAllowed(String endpoint, String whitelist) {
        String host = effectiveHost(endpoint);
        List<String> patterns = patterns(whitelist);
        if (!matchesAny(host, patterns)) {
            throw new KmsPluginException("KMS endpoint '" + endpoint + "' is not matched by the endpoint whitelist ["
                    + String.join(", ", patterns) + "]");
        }
    }

    /**
     * The host the SDK actually connects to. {@code Tea.composeUrl} builds
     * {@code protocol + "://" + endpoint + path}, so the endpoint is parsed as a URI authority and
     * {@code kms.cn-hangzhou.aliyuncs.com@localhost} connects to {@code localhost}. Matching the raw
     * string instead would let that through.
     */
    private static String effectiveHost(String endpoint) {
        URI uri;
        try {
            uri = new URI("https://" + endpoint.trim() + "/");
        } catch (URISyntaxException e) {
            throw new KmsPluginException("KMS endpoint '" + endpoint + "' is not a valid host name", e);
        }
        if (uri.getUserInfo() != null) {
            throw new KmsPluginException("KMS endpoint '" + endpoint + "' must not contain credentials");
        }
        String host = uri.getHost();
        if (host == null) {
            throw new KmsPluginException("KMS endpoint '" + endpoint + "' is not a valid host name");
        }
        return host.toLowerCase(Locale.ROOT);
    }

    /** Comma-separated, trimmed and lower-cased; a blank list falls back to the default pattern. */
    private static List<String> patterns(String whitelist) {
        List<String> patterns = new ArrayList<>();
        for (String pattern : StringUtils.split(StringUtils.defaultString(whitelist), ',')) {
            String trimmed = pattern.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                patterns.add(trimmed);
            }
        }
        if (patterns.isEmpty()) {
            patterns.add(KmsGlobalConfiguration.DEFAULT_STEP_ENDPOINT_WHITELIST);
        }
        return patterns;
    }

    private static boolean matchesAny(String host, List<String> patterns) {
        for (String pattern : patterns) {
            if (globMatches(host, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@code *} stands for any run of characters, dots included; every other character is literal. Walked
     * by hand rather than compiled into a regex so that no part of a configured pattern can be read as a
     * metacharacter.
     */
    private static boolean globMatches(String host, String pattern) {
        int hostIndex = 0;
        int patternIndex = 0;
        int star = -1;
        int backtrack = 0;
        while (hostIndex < host.length()) {
            if (patternIndex < pattern.length() && pattern.charAt(patternIndex) == host.charAt(hostIndex)) {
                hostIndex++;
                patternIndex++;
            } else if (patternIndex < pattern.length() && pattern.charAt(patternIndex) == '*') {
                star = patternIndex++;
                backtrack = hostIndex;
            } else if (star >= 0) {
                patternIndex = star + 1;
                hostIndex = ++backtrack;
            } else {
                return false;
            }
        }
        while (patternIndex < pattern.length() && pattern.charAt(patternIndex) == '*') {
            patternIndex++;
        }
        return patternIndex == pattern.length();
    }
}
