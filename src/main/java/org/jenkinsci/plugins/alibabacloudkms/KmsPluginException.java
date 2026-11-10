package org.jenkinsci.plugins.alibabacloudkms;

public class KmsPluginException extends RuntimeException {

    public KmsPluginException(String message) {
        super(message);
    }

    public KmsPluginException(String message, Throwable cause) {
        super(message, cause);
    }
}
