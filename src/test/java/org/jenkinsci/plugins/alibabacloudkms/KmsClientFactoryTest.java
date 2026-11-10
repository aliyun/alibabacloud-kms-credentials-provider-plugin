package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Covers endpoint validation in {@link KmsClientFactory}. Authentication is the Alibaba Cloud default
 * credential chain, whose resolution depends on the ambient environment, so the signed-credential path
 * is exercised by the acceptance IT rather than here.
 */
public class KmsClientFactoryTest {

    @Test
    public void blankEndpointFailsWhenTheClientIsBuilt() {
        KmsPluginException e =
                assertThrows(KmsPluginException.class, () -> KmsClientFactory.createClient("  "));
        assertTrue(e.getMessage(), e.getMessage().contains("endpoint"));
    }
}
