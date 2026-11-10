# Alibaba Cloud KMS Credentials Provider Plugin

Fetch secrets from [Alibaba Cloud KMS Secrets Manager](https://www.alibabacloud.com/help/en/kms/) and use them in your Jenkins jobs.

The plugin has three capabilities, each usable on its own:

1. **Credentials provider** — maps KMS secrets into read-only Jenkins credentials (Secret text, Username with password, SSH user private key, Certificate, Secret file), so they can be selected anywhere a normal Jenkins credential is accepted.
2. **Pipeline step** — a `withAlibabaCloudKms` build wrapper that binds named KMS secrets to environment variables for the duration of a build.
3. **Configuration as Code secret source** — resolves `${secret}` placeholders inside JCasC YAML at controller startup.

## Contents

- [Setup](#setup)
  - [Authentication](#authentication)
  - [System configuration](#system-configuration)
- [Credentials provider](#credentials-provider)
  - [Selecting secrets with a tag](#selecting-secrets-with-a-tag)
  - [Credential types](#credential-types)
  - [Managed (rotating) secrets](#managed-rotating-secrets)
  - [Jenkins credential ID, description and scope](#jenkins-credential-id-description-and-scope)
- [Pipeline step](#pipeline-step)
  - [Scripted](#scripted)
  - [Declarative](#declarative)
  - [Secret files](#secret-files)
  - [Overrides](#overrides)
- [Configuration as Code secret source](#configuration-as-code-secret-source)
- [Masking](#masking)
- [Building and installing the plugin](#building-and-installing-the-plugin)
  - [Build from source](#build-from-source)
  - [Install into a controller](#install-into-a-controller)
  - [Verify the install](#verify-the-install)

## Setup

### Authentication

The plugin has no AccessKey setting of its own; authentication is the **Alibaba Cloud default credential chain** and nothing else. The plugin builds a single `com.aliyun.credentials.Client`, which resolves credentials from the environment in the standard order — the `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET` environment variables, an OIDC role, a `~/.alibabacloud/credentials` file, or the RAM role of the ECS/ACK instance the controller runs on. That last one is the recommended path.

There is deliberately no *Credential ID* setting pointing at a stored `AlibabaCredentials` credential: every published version of the Alibaba Cloud Credentials Plugin requires Jenkins 2.190.1 or later, so it cannot be installed on this plugin's 2.138.4 baseline.

The RAM identity needs read access to Secrets Manager:

- `kms:ListSecrets` — discovers secrets and returns their tags in the same call, so no separate describe permission is needed
- `kms:GetSecretValue` — reads each secret's value on use

### System configuration

Every setting can be supplied through the UI, a JVM system property, or an environment variable. An environment variable wins over a system property, and either wins over the persisted UI value, so any of them can be injected at startup without being written to disk.

| Setting | UI field | System property | Environment variable | Default |
| --- | --- | --- | --- | --- |
| Endpoint | *Endpoint* | `jenkins.alibabacloud-kms.endpoint` | `ALIBABA_CLOUD_KMS_ENDPOINT` | *(none — required)* |
| Step endpoint whitelist | *Step endpoint whitelist* | `jenkins.alibabacloud-kms.stepEndpointWhitelist` | `ALIBABA_CLOUD_KMS_STEP_ENDPOINT_WHITELIST` | `*.aliyuncs.com` |
| Tag selector | *Tag Key* | `jenkins.alibabacloud-kms.tagKey` | `ALIBABA_CLOUD_KMS_TAG_KEY` | `jenkins:credentials` |
| Cache TTL (seconds) | *Cache time (seconds)* | `jenkins.alibabacloud-kms.cacheSeconds` | `ALIBABA_CLOUD_KMS_CACHE_SECONDS` | `300` (`0` = never cache) |

The **Endpoint** is the KMS regional endpoint, e.g. `kms.cn-hangzhou.aliyuncs.com`.

The **Step endpoint whitelist** is a comma-separated list of host patterns that the `endpoint:` argument of `withAlibabaCloudKms` has to match. `*` stands for any run of characters, dots included; everything else is literal, matching is case-insensitive, and only the host is constrained, not the port. Naming an endpoint is the one part of a KMS call a pipeline author controls with Job/Configure alone, so this is what stops a job from making the controller open a connection to a host of its choosing, signed with the controller's own Alibaba Cloud identity, and read that host's reply back through the build log.

The **Endpoint** above is not covered by it, and neither is the endpoint the `${...}` placeholders resolve against. Those are set by an administrator — through the Overall/Administer gated system configuration, an environment variable or a system property — so whoever set them was already trusted with where the controller talks to. A step that leaves its own `endpoint:` empty inherits the global one and is therefore not checked either.

Widen the whitelist only as far as your pipelines require: an exact host name is stricter than a pattern, and `*` on its own switches the check off. It bounds which host the controller contacts first, not where that host may send it — the Alibaba Cloud SDK follows redirects and offers no switch to stop it.

#### Via UI

Go to **Manage Jenkins → Configure System → Alibaba Cloud KMS Credentials** and set the fields above.

#### Via Configuration as Code

```yaml
unclassified:
  alibabaCloudKms:
    endpoint: "kms.cn-hangzhou.aliyuncs.com"
    stepEndpointWhitelist: "*.aliyuncs.com"
    tagKey: "jenkins:credentials"
    cacheSeconds: 600
```

#### Via system properties

```bash
-Djenkins.alibabacloud-kms.endpoint=kms.cn-hangzhou.aliyuncs.com
-Djenkins.alibabacloud-kms.stepEndpointWhitelist=*.aliyuncs.com
-Djenkins.alibabacloud-kms.tagKey=jenkins:credentials
-Djenkins.alibabacloud-kms.cacheSeconds=600
```

#### Via environment variables

```bash
ALIBABA_CLOUD_KMS_ENDPOINT=kms.cn-hangzhou.aliyuncs.com
ALIBABA_CLOUD_KMS_STEP_ENDPOINT_WHITELIST=*.aliyuncs.com
ALIBABA_CLOUD_KMS_TAG_KEY=jenkins:credentials
ALIBABA_CLOUD_KMS_CACHE_SECONDS=600
```

## Credentials provider

The provider gives a **read-only** view of Secrets Manager. Credentials are listed and mapped from secret metadata, and each secret's value is fetched from KMS on use and then cached for *Cache time (seconds)* (default 5 minutes; set it to `0` to never cache and read live every time). This applies to every credential type, including managed username/password pairs. A rotated secret is picked up promptly regardless of that lifetime, because the credential is keyed on the secret's `updateTime`; the lifetime only bounds repeated reads of an *unchanged* secret. Credential *discovery* (new, deleted or re-tagged secrets) runs on its own fixed 30-second window, so membership changes may not appear immediately — reload the cache from the system configuration page to force one now.

A secret with no `jenkins:credentials:id` tag uses its KMS secret name as the Jenkins credential ID. Nothing validates it — Jenkins enforces no character set on an ID — but sticking to `[a-zA-Z0-9_.-]+` keeps the value a job has to type in `credentialsId:` predictable. If two secrets resolve to the same Jenkins credential ID, the second is skipped and a warning is logged.

### Selecting secrets with a tag

Only secrets carrying a matching tag are listed. The selector is the configured **Tag Key** (default `jenkins:credentials`), matched **case-sensitively as a substring of each secret's tag keys** — a secret is included when at least one of its tag keys contains this text. Because every `jenkins:credentials:*` tag contains that substring, tagging a secret with any of the type tags below is enough to make it visible.

### Credential types

Each secret's tags drive how it is mapped. The controlling tag is `jenkins:credentials:type`; when it is absent the type defaults to `string`. It is the only tag that selects the type — every other `jenkins:credentials:*` tag just supplies a value to the type that asks for one, so a `jenkins:credentials:username` tag on a secret that does not say `username` or `sshUserPrivateKey` is ignored.

| `jenkins:credentials:type` | Jenkins credential | Secret value | Extra tags |
| --- | --- | --- | --- |
| `string` *(default)* | Secret text | the secret | — |
| `username` | Username with password | the password | `jenkins:credentials:username` |
| `secretFile` | Secret file | the file content | `jenkins:credentials:filename` (default `<secretName>.txt`) |
| `sshUserPrivateKey` | SSH username with private key | the private key | `jenkins:credentials:username`, `jenkins:credentials:passphrase-id` |
| `certificate` | Certificate | the keystore | `jenkins:credentials:password-id` |

Tag reference:

- `jenkins:credentials:username` — username for `username` and `sshUserPrivateKey` types. When non-blank it wins outright, so listing credentials costs no KMS calls. When it is absent the username comes from inside a managed secret's value; a plain `username` secret has no such value, so its username is empty and a credential picker renders that entry as `/******`. Projected credentials also always carry an empty description, which is why the same picker appends ` ()` to every entry — both are visible signals that a tag is missing, not rendering bugs.
- `jenkins:credentials:filename` — file name used when a `secretFile` credential is written to disk by `withCredentials([file(...)])`, which puts it in a temporary directory outside the workspace and binds the path.
- `jenkins:credentials:passphrase-id` — name of another secret holding the SSH key passphrase.
- `jenkins:credentials:password-id` — name of another secret holding the certificate keystore password.
- `jenkins:credentials:auto-parse-secret` — `true` to treat the value as a [managed secret](#managed-rotating-secrets) and parse the account/password pair out of its JSON payload.

The `passphrase-id` / `password-id` tags reference a **separate** secret. When the tag is absent the referenced value is empty; when it names a secret that cannot be read, the credential fails at the point of use rather than silently binding an empty value.

#### Example: secret text

```bash
aliyun kms CreateSecret \
  --SecretName newrelic-api-key \
  --SecretData 'abc123' \
  --Tags '[{"TagKey":"jenkins:credentials:type","TagValue":"string"}]'
```

Scripted pipeline:

```groovy
node {
    withCredentials([string(credentialsId: 'newrelic-api-key', variable: 'NEWRELIC_API_KEY')]) {
        sh 'echo "$NEWRELIC_API_KEY"'
    }
}
```

#### Example: username with password

```bash
aliyun kms CreateSecret \
  --SecretName artifactory \
  --SecretData 'supersecret' \
  --Tags '[{"TagKey":"jenkins:credentials:type","TagValue":"username"},{"TagKey":"jenkins:credentials:username","TagValue":"joe"}]'
```

```groovy
node {
    withCredentials([usernamePassword(credentialsId: 'artifactory', usernameVariable: 'ARTIFACTORY_USR', passwordVariable: 'ARTIFACTORY_PSW')]) {
        sh 'echo "$ARTIFACTORY_USR"'
    }
}
```

#### Example: SSH user private key

```bash
aliyun kms CreateSecret \
  --SecretName ssh-key \
  --SecretData "$(cat id_rsa)" \
  --Tags '[{"TagKey":"jenkins:credentials:type","TagValue":"sshUserPrivateKey"},{"TagKey":"jenkins:credentials:username","TagValue":"joe"}]'
```

```groovy
node {
    withCredentials([sshUserPrivateKey(credentialsId: 'ssh-key', keyFileVariable: 'KEY', usernameVariable: 'KEY_USR')]) {
        sh 'ssh -i "$KEY" "$KEY_USR"@host "uname -r"'
    }
}
```

#### Example: certificate

Store the keystore in the secret and, if it is password-protected, put the password in a separate secret referenced by `jenkins:credentials:password-id`.

```groovy
node {
    withCredentials([certificate(credentialsId: 'code-signing-cert', keystoreVariable: 'STORE_FILE', passwordVariable: 'STORE_PASSWORD')]) {
        sh 'curl --cert-type P12 --cert "$STORE_FILE":"$STORE_PASSWORD" https://example.com'
    }
}
```

#### Example: secret file

```groovy
node {
    withCredentials([file(credentialsId: 'license-key', variable: 'LICENSE_KEY_FILE')]) {
        sh 'do-something --use "$LICENSE_KEY_FILE"'
    }
}
```

### Managed (rotating) secrets

KMS *managed* secrets hold a JSON account/password pair rather than a bare string, and rotate it on a schedule. Add `jenkins:credentials:auto-parse-secret=true` (with `jenkins:credentials:type=username`) to parse the pair out of the payload. Both halves are read from the **same** payload, so a rotation that replaces both the id and the secret stays consistent. The pair is cached for *Cache time (seconds)* like any other value (`0` reads it live every time), and a rotation is picked up promptly regardless because the credential is keyed on the secret's `updateTime`. A failed read is remembered for 30 seconds before it is retried — even at `0` — so an outage costs one timeout per secret rather than one per dropdown entry.

Supported managed secret types — the type literal is **case-sensitive**:

| Secret type | Username field | Password field |
| --- | --- | --- |
| `Rds` | `AccountName` | `AccountPassword` |
| `Redis` | `AccountName` | `AccountPassword` |
| `PolarDB` | `AccountName` | `AccountPassword` |
| `ECS` | `UserName` | `Password` |
| `RAMCredentials` | `AccessKeyId` | `AccessKeySecret` |

`GetSecretValue` returns every managed type as a flat object. The `{"Accounts":[{"AccountName":...,"AccountPassword":...}]}` shape is only the `CreateSecret` *input* for an `Rds` secret — KMS never returns it, so it is not read.

The `RAMCredentials` type maps a rotating RAM user's AccessKey pair onto the username and password of a Jenkins credential. Because RAM deletes the old AccessKey outright on rotation, both halves must be read together and re-read often.

### Jenkins credential ID, description and scope

- `jenkins:credentials:id` — the Jenkins credential ID (the value used in `credentialsId:`). Defaults to the secret name.
- **Description** — always empty: no KMS tag maps onto a Jenkins credential description, so projected credentials carry none.
- `jenkins:credentials:scope` — `GLOBAL` (default) or `SYSTEM`. A `SYSTEM`-scoped credential is only visible when the lookup context is Jenkins itself.

## Pipeline step

`withAlibabaCloudKms` binds named KMS secrets to environment variables for the duration of its block. Each entry is a `KmsSecret` with:

- `secretType` — `Secret` (bind the value directly) or `File` (write the value to a file outside the workspace and bind its path).
- `name` — the KMS secret name.
- `envVariable` — the environment variable to set.
- `version` *(optional)* — a specific secret version id.

For a **managed** secret (`Rds`, `Redis`, `PolarDB`, `ECS`, `RAMCredentials`), the step binds three variables: the full JSON payload to `envVariable`, plus the parsed pair to `<envVariable>_USERNAME` and `<envVariable>_PASSWORD`. All three are masked — notably, a RAM secret's `AccessKeyId` is masked here, unlike under `withCredentials`, which masks the password alone.

### Scripted

```groovy
node {
    def secrets = [
        [secretType: 'Secret', name: 'my-secret', envVariable: 'MY_SECRET'],
        [secretType: 'Secret', name: 'my-secret', version: 'v2', envVariable: 'MY_SECRET_V2']
    ]

    withAlibabaCloudKms(secrets) {
        sh 'echo "$MY_SECRET"'
    }
}
```

Managed secret:

```groovy
node {
    withAlibabaCloudKms([[secretType: 'Secret', name: 'my-rds-secret', envVariable: 'DB']]) {
        // DB = full JSON payload, DB_USERNAME / DB_PASSWORD = parsed pair
        sh 'mysql -u "$DB_USERNAME" -p"$DB_PASSWORD" -e "select 1"'
    }
}
```

### Declarative

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                withAlibabaCloudKms([[secretType: 'Secret', name: 'my-secret', envVariable: 'MY_SECRET']]) {
                    sh 'echo "$MY_SECRET"'
                }
            }
        }
    }
}
```

### Secret files

A `File` secret is written to a temporary file in the workspace's `@tmp` sibling directory (`<workspace>@tmp/kms-secrets/`), deliberately **not** inside the workspace itself, so the plaintext stays out of reach of workspace browsing and of an `archiveArtifacts '**/*'` running in the same step. The environment variable is set to the file's **path**. Binary secrets (KMS `SecretDataType=binary`) are base64-decoded back to their raw bytes on write. The file is deleted when the block finishes, so plaintext does not outlive the step on a shared or reused agent. A `File` secret requires a `node` context.

```groovy
node {
    withAlibabaCloudKms([[secretType: 'File', name: 'my-keyfile', envVariable: 'KEY_FILE']]) {
        sh 'openssl pkey -in "$KEY_FILE" -noout'
    }
}
```

### Overrides

The endpoint is the only per-step override; authentication always comes from the controller JVM's default credential chain. An empty `endpoint` on the step falls back to the globally configured one, and when both are empty the step fails with `No Alibaba Cloud KMS endpoint configured, set one globally or on the step`. An endpoint named *on the step* additionally has to match the *Step endpoint whitelist*, which a job cannot widen: a step naming a host outside it fails with `KMS endpoint '...' is not matched by the endpoint whitelist [...]` before any connection is made. Inheriting the global endpoint is not checked, because that value was set by an administrator.

```groovy
node {
    withAlibabaCloudKms(
        secrets: [[secretType: 'Secret', name: 'my-secret', envVariable: 'MY_SECRET']],
        endpoint: 'kms.cn-shanghai.aliyuncs.com'
    ) {
        sh 'echo "$MY_SECRET"'
    }
}
```

## Configuration as Code secret source

The plugin registers a JCasC `SecretSource`, so `${...}` placeholders inside a JCasC YAML file are resolved from KMS **at controller startup**, before beans are constructed. This lets Configuration as Code interpolate secrets without storing them on disk.

```yaml
jenkins:
  securityRealm:
    local:
      allowsSignup: false
      users:
        - id: "admin"
          password: "${admin-initial-password}"
```

**Bootstrap caveat.** JCasC resolves `${...}` while parsing the YAML, *before* the `unclassified.alibabaCloudKms` bean in the same file is applied. The secret source therefore cannot rely on an endpoint defined in the very YAML it is interpolating. Supply the endpoint (and authentication) through a channel available at boot:

```bash
java -Djenkins.alibabacloud-kms.endpoint=kms.cn-hangzhou.aliyuncs.com \
     -jar jenkins.war
```

with credentials coming from the default credential chain (`ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, an OIDC role, a `~/.alibabacloud/credentials` file, or an instance RAM role). Nothing on this path reads the Jenkins credential store, so the caveat is about the endpoint alone: a document that both defines credentials and interpolates `${...}` from KMS resolves fine, because resolution never depends on a bean that the same document is still in the middle of defining.

**Failure handling.** Once an endpoint is configured, `reveal` splits failures the way the JCasC `SecretSource` contract asks a source to:

- **Recoverable — handed back to the resolver chain.** KMS answered that it has no such secret (`Forbidden.ResourceNotFound`, HTTP 404). That is logged at `INFO` and the placeholder is left to the remaining sources, so JCasC applies its own default. This is the *only* outcome treated as recoverable.
- **Unrecoverable — the apply fails.** The endpoint does not resolve, the connection is refused or times out, KMS rejects the credential (401/403), or no KMS client could be built at all. `reveal` reports it, the configuration apply stops and the controller does not start. The alternative is the empty string JCasC substitutes for an unresolved variable, which yields a controller that looks perfectly healthy with a blanked password and no error anywhere.

A placeholder that is genuinely meant to be optional can say so with `${name:-}`, which is handled by JCasC and never reaches this plugin.

With no endpoint configured the source stays inert and fails nothing, so installing the plugin cannot break a controller that uses `${...}` for environment variables or property files.

**Ordering.** A lookup this source cannot carry out fails the whole apply, so it registers with a negative ordinal and is consulted *after* the built-in Docker, environment and properties sources. A placeholder any of those can resolve never reaches KMS.

**Failing on placeholders this plugin never sees.** The above only governs lookups this plugin makes, and a name KMS does not know is deliberately left unresolved rather than fatal. With no endpoint configured the source stays inert altogether. Either way the placeholder ends up in Configuration as Code's own hands, and the 1.35 release this plugin builds against logs

```
Configuration import: Found unresolved variable <name>. Will default to empty string
```

at `WARNING` and substitutes the empty string — so a typo still yields a blank setting rather than an error. That log line is the only signal available here; grep for it after a configuration apply.

Later Configuration as Code releases add a strict switch that aborts the apply instead, with `Unable to resolve variable '<name>'. Aborting configuration reload.`:

```bash
java -Dcasc.strict.secret.resolution=true \
     -jar jenkins.war
```

Equivalently, `CASC_STRICT_SECRET_RESOLUTION=true` in the environment. It belongs to Configuration as Code, not to this plugin, and **1.35 does not have it**: the release that introduced it declares Jenkins 2.541.1 as its minimum core, so it cannot be installed alongside this plugin on a 2.138.4 controller and setting the switch there does nothing at all.

## Masking

Inside a `withAlibabaCloudKms` block the plugin installs its own `ConsoleLogFilter` on the build log. Every bound value is folded into a single alternation — `Pattern.quote`d, so a value's own regex metacharacters cannot leak structure into the log, and ordered longest-first, so a value that is a substring of another is masked as the longer one — and each match is replaced with `****`. That covers the parsed halves of a managed secret too, so a RAM secret's `AccessKeyId` is masked here, unlike under `withCredentials`, which masks the password alone. Credentials surfaced through the provider are masked by the standard `withCredentials` machinery instead.

The filter is the plugin's own because Credentials Binding is not a runtime dependency of this plugin — only its tests reach for it — so nothing in `src/main` may call that plugin's `SecretPatterns`.

Masking is best-effort. It matches the literal value, line by line:

- A value spanning more than one log line is never matched. A private key bound with `secretType: 'File'` is unaffected — only its path reaches the log — but one bound as `Secret` and echoed verbatim is multi-line, and so is not masked.
- The shell-quoting variants credentials-binding adds are not reproduced, and a value a step transforms (base64-encoded, URL-encoded, split, re-cased) appears as transformed.
- There is no minimum length. A very short value is masked wherever it occurs, which also means it can eat ordinary text.

## Building and installing the plugin

Requires **JDK 8–11** (enforcer gate `[1.8,12)`; the build is verified on JDK 8) and **Maven** to build. The resulting plugin declares **Jenkins 2.138.4** as its minimum core version and is written against that era's API — the Java 8 language level and `org.acegisecurity.*`, the security API Jenkins replaced with Spring Security in 2.266 — so it targets controllers of that vintage rather than a current LTS.

### Build from source

```bash
mvn package          # produces target/alibabacloud-kms-credentials-provider.hpi
```

The `.hpi` file under `target/` is the installable plugin artifact (the plugin short name is `alibabacloud-kms-credentials-provider`; the `.hpi` filename carries no version suffix).

Run the unit test suite:

```bash
mvn test
```

The acceptance tests (`*IT.java`, which exercise the plugin against a real KMS environment) live behind a profile, run under `failsafe`, and need their target named:

```bash
mvn verify -Pkms-acceptance \
  -Dkms.acceptance.endpoint=kms.cn-shanghai.aliyuncs.com \
  -Dkms.acceptance.dkms-instance-id=kst-xxxxxxxxxxxxxxxxxxxx \
  -Dkms.acceptance.rds.instance-id=rm-xxxxxxxxxxxxxxxxxxxx \
  -Dkms.acceptance.rds.account-name=some_account
```

**These perform real writes.** A run creates around ten secrets on a DKMS instance, drives a real pipeline over them, and then force-deletes exactly the ones it created. It needs credentials for the target environment on the Alibaba Cloud default credential chain, and the target itself named — in `kms-acceptance.properties`, or on the command line as above, which takes precedence. With that file filled in, `mvn verify -Pkms-acceptance` on its own is enough.

[`kms-acceptance.template.properties`](src/test/resources/kms-acceptance.template.properties) is the tracked half of the pair: it documents every key and leaves each one that names a cloud resource blank, so the repository names no environment and a run cannot inherit one by accident. Copy it to `src/test/resources/kms-acceptance.properties` and fill in the endpoint, the DKMS instance and the RDS instance and account behind the managed `Rds` fixture — that file is gitignored, because what belongs in it is which KMS *your* run writes to. Passing the same keys with `-D<key>=<value>` works as well and overrides the file. Only the naming prefixes that keep a run's secrets distinguishable from everybody else's on a shared gateway are defaulted.

Another environment needs a DKMS instance holding an enabled `Aliyun_AES_256` key, and, for the managed `Rds` fixture, a real RDS instance and account in that same environment. The run passes that endpoint to `withAlibabaCloudKms`, so the step endpoint whitelist applies to it: any host matching the default `*.aliyuncs.com` can be named, and one that does not also needs `-Djenkins.alibabacloud-kms.stepEndpointWhitelist=<pattern>`. Whichever it is, the run only ever deletes the secrets it created itself, each named `<secret-name-prefix>-<runId>-<logicalName>` and tagged `<selector-tag-prefix>:<runId>`, so aiming it somewhere unintended leaves that place with no residue rather than missing data.

The RDS instance and account go stale roughly monthly. When they do, the run fails while creating the `rds` fixture with `Forbidden.ResourceNotFound`, which is also what KMS reports for an unknown account name and for a permission failure alike, so the message cannot tell those apart: check those two values before suspecting the code.

### Install into a controller

Pick one of the following.

**A. Upload through the UI** — easiest for an existing controller.

1. Build the `.hpi` (above).
2. Go to **Manage Jenkins → Manage Plugins → Advanced**.
3. Under **Upload Plugin**, choose the `target/*.hpi` file and click **Upload**.
4. Restart Jenkins when prompted.

**B. Drop into `$JENKINS_HOME/plugins`** — good for scripted/offline installs.

```bash
cp target/alibabacloud-kms-credentials-provider.hpi "$JENKINS_HOME/plugins/"
```

Then restart the controller. Jenkins unpacks the `.hpi` on startup into `$JENKINS_HOME/plugins/alibabacloud-kms-credentials-provider/`. If an older version is already installed, overwrite the `.hpi` and restart; remove any stale exploded directory (`$JENKINS_HOME/plugins/alibabacloud-kms-credentials-provider/`) if the new version does not take effect.

**C. Run a throwaway controller for local development** — no install step.

```bash
mvn hpi:run
```

This launches a development Jenkins (by default at <http://localhost:8080/jenkins>) with the plugin loaded from the working tree.

### Verify the install

After restart, confirm the plugin is active under **Manage Jenkins → Manage Plugins → Installed** (search "Alibaba Cloud KMS"), then set the endpoint under **Manage Jenkins → Configure System → Alibaba Cloud KMS Credentials**.

> **Note on hot-reloading a rebuilt plugin.** A plugin that is already active cannot be hot-swapped in place — attempting to reload it dynamically raises `RestartRequiredException`. Rebuild-and-reload workflows therefore need a full controller restart, not a dynamic load.

