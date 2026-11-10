/*
 * `buildPlugin` comes from the `jenkins-pipeline-library` shared library, which ci.jenkins.io loads
 * implicitly. Any other controller must either configure it as an implicitly loaded global library
 * or uncomment the annotation below, otherwise the run dies on "No such DSL method 'buildPlugin'".
 */
// @Library('jenkins-pipeline-library') _

/*
 * This pom targets Jenkins core 2.138.4 at the Java 8 language level (`java.level=8`; there is no
 * `maven.compiler.release`), so '8' is the JDK that builds it. Both `platform` and `jdk` are required
 * per entry — omitting either is a hard error, not a fallback.
 *
 * `useContainerAgent: false` makes the library resolve the JDK and Maven from the controller's tool
 * installations rather than from a container image, so the jdk value below names a configured tool.
 * The trade-off: incrementals are only published from container agents.
 */
buildPlugin(
        useContainerAgent: false,
        configurations: [
                [platform: 'linux', jdk: '8'],
                [platform: 'windows', jdk: '8'],
        ])
