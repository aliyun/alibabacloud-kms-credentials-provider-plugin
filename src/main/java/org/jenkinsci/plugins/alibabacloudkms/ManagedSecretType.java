package org.jenkinsci.plugins.alibabacloudkms;

import java.util.Optional;
import org.apache.commons.lang3.StringUtils;

/**
 * Managed KMS secret types whose {@code GetSecretValue} payload is a JSON object holding a
 * well-known account name / password pair.
 *
 * <p>The type literals are case sensitive: KMS returns the {@code SecretType} as {@code Rds}, not
 * {@code RDS}, so matching against it must be exact.</p>
 */
public enum ManagedSecretType {
    RDS("Rds", "AccountName", "AccountPassword"),
    REDIS("Redis", "AccountName", "AccountPassword"),
    POLARDB("PolarDB", "AccountName", "AccountPassword"),
    ECS("ECS", "UserName", "Password"),

    /**
     * Rotating RAM user secret: the payload is an AccessKey pair, mapped onto the username and
     * password of a Jenkins credential. Rotation replaces the AccessKeyId as well as the secret, and
     * RAM deletes the old pair outright, so both halves have to be read from the same payload and
     * re-read often.
     */
    RAM("RAMCredentials", "AccessKeyId", "AccessKeySecret");

    private final String secretType;
    private final String usernameKey;
    private final String passwordKey;

    ManagedSecretType(String secretType, String usernameKey, String passwordKey) {
        this.secretType = secretType;
        this.usernameKey = usernameKey;
        this.passwordKey = passwordKey;
    }

    public static Optional<ManagedSecretType> from(String secretType) {
        if (StringUtils.isBlank(secretType)) {
            return Optional.empty();
        }
        for (ManagedSecretType type : values()) {
            if (type.secretType.equals(secretType)) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    public String usernameKey() {
        return usernameKey;
    }

    public String passwordKey() {
        return passwordKey;
    }
}
