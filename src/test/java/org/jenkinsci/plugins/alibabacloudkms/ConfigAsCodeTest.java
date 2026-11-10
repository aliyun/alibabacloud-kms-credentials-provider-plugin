package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.aliyun.tea.TeaException;
import com.aliyun.tea.TeaRetryableException;
import com.aliyun.tea.TeaUnretryableException;
import hudson.ExtensionList;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.SecretSource;
import io.jenkins.plugins.casc.SecretSourceResolver;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;

public class ConfigAsCodeTest {

    @Rule public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("global-config.yml")
    public void configuresGlobalSettingsFromYaml() {
        KmsGlobalConfiguration configuration = KmsGlobalConfiguration.get();
        assertEquals("kms.cn-hangzhou.aliyuncs.com", configuration.getEndpoint());
        assertEquals("jenkins:credentials", configuration.getTagKey());
        assertEquals(600L, configuration.getCacheSeconds());
    }

    @Test
    @ConfiguredWithCode("global-config.yml")
    public void exportsGlobalSettings() throws Exception {
        KmsGlobalConfiguration configuration = KmsGlobalConfiguration.get();

        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        Configurator<KmsGlobalConfiguration> configurator = context.lookupOrFail(KmsGlobalConfiguration.class);

        CNode node = configurator.describe(configuration, context);
        assertNotNull(node);
        Mapping mapping = node.asMapping();
        assertEquals("kms.cn-hangzhou.aliyuncs.com", mapping.getScalarValue("endpoint"));
    }

    @Test
    public void registersKmsSecretSource() {
        boolean present = ExtensionList.lookup(SecretSource.class).stream().anyMatch(KmsSecretSource.class::isInstance);
        assertTrue("KmsSecretSource should be registered so ${secret} placeholders resolve from KMS", present);
    }

    @Test
    public void revealIsInertWithoutEndpoint() throws Exception {
        // A controller with no KMS endpoint configured must not attempt any lookup, so casc leaves
        // the placeholder to other secret sources instead of failing start-up.
        assertFalse(new KmsSecretSource().reveal("any-secret").isPresent());
        assertFalse(new KmsSecretSource().reveal("  ").isPresent());
    }

    @Test
    public void revealFailsTheApplyWhenKmsCannotBeReached() {
        configureUnreachableEndpoint();

        // "All attempts to contact the backing store have failed" is unrecoverable per the SecretSource
        // contract, and swallowing it would import the configuration with every KMS-backed setting blanked.
        assertFailsRevealing("any-secret");
    }

    @Test
    public void aMissingSecretIsRecoverableButARejectedCredentialIsNot() {
        assertTrue(KmsSecretSource.kmsSaidNotFound(new KmsPluginException("wrapped", kmsError(404))));
        assertFalse(KmsSecretSource.kmsSaidNotFound(new KmsPluginException("wrapped", kmsError(403))));
        assertFalse(KmsSecretSource.kmsSaidNotFound(new KmsPluginException("wrapped", kmsError(500))));
        assertFalse(KmsSecretSource.kmsSaidNotFound(new KmsPluginException(
                "wrapped",
                new TeaUnretryableException(new TeaRetryableException(new UnknownHostException("kms.invalid"))))));
        assertFalse(KmsSecretSource.kmsSaidNotFound(new KmsPluginException("no cause, so nothing answered")));
        // The SDK throws TeaException for reasons that never produced a response either; only the status
        // separates "KMS answered 404" from those.
        assertFalse(KmsSecretSource.kmsSaidNotFound(new TeaException(
                Collections.singletonMap("message", "no status at all"))));
    }

    @Test
    public void isConsultedAfterEveryBuiltInSecretSource() {
        // A lookup we cannot carry out fails the whole apply, which is only safe while a placeholder that
        // another source can resolve never reaches us first. The built-ins all use the default ordinal, so
        // a negative one puts us last by contract rather than by discovery order.
        List<SecretSource> sources = ExtensionList.lookup(SecretSource.class);
        assertEquals(KmsSecretSource.class, sources.get(sources.size() - 1).getClass());
    }

    @Test
    public void cascAbortsTheApplyRatherThanSubstitutingAnEmptyString() {
        configureUnreachableEndpoint();

        // Throwing only helps if casc actually stops. It calls reveal inside a stream wrapped in
        // unchecked(...), which sneaky-throws rather than rewraps, so our IOException surfaces with its
        // type intact and the resolver chain never reaches the pass that defaults unresolved variables
        // to "".
        ConfigurationContext context = new ConfigurationContext(ConfiguratorRegistry.get());
        IOException e = assertThrows(
                IOException.class, () -> SecretSourceResolver.resolve(context, "password: ${any-secret}"));
        assertTrue(e.getMessage(), e.getMessage().contains("any-secret"));
    }

    private static void assertFailsRevealing(String secret) {
        // A controller that comes up with a setting silently blanked is indistinguishable from a healthy
        // one, so an unrecoverable lookup has to stop the configuration apply instead of resolving to "".
        IOException e = assertThrows(IOException.class, () -> new KmsSecretSource().reveal(secret));
        assertTrue(e.getMessage(), e.getMessage().contains(secret));
    }

    /** {@code .invalid} is reserved to never resolve, so the lookup fails at DNS instead of timing out. */
    private static void configureUnreachableEndpoint() {
        KmsGlobalConfiguration configuration = KmsGlobalConfiguration.get();
        configuration.setEndpoint("kms.invalid");
    }

    /**
     * The shape a KMS error response arrives in: KMS reports a missing secret as
     * {@code Forbidden.ResourceNotFound} with a 404 status, which the SDK hands up as a
     * {@code TeaException} carrying that status.
     */
    private static TeaException kmsError(int statusCode) {
        Map<String, Object> error = new HashMap<>();
        error.put("code", "Forbidden.ResourceNotFound");
        error.put("message", "code: " + statusCode);
        error.put("data", Collections.singletonMap("statusCode", statusCode));
        return new TeaException(error);
    }
}
