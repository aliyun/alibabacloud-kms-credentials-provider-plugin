package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockFolder;

/**
 * A SYSTEM-scoped credential is filtered on {@code itemGroup instanceof Jenkins}, so the item group that
 * reaches the filter is what decides whether a job can see one at all. These assert on that resolution
 * rather than on a returned credential list: no KMS endpoint is configured here, so the list is empty
 * either way and would not distinguish the two.
 */
public class CredentialsProviderScopeTest {

    @Rule public JenkinsRule jenkins = new JenkinsRule();

    private static final List<DomainRequirement> NO_REQUIREMENTS = Collections.emptyList();

    @Test
    public void aTopLevelJobResolvesToTheJenkinsRootSoSystemCredentialsStayVisible() throws Exception {
        FreeStyleProject job = jenkins.createProject(FreeStyleProject.class, "top-level");
        RecordingProvider provider = new RecordingProvider();

        provider.getCredentials(Credentials.class, job, ACL.SYSTEM, NO_REQUIREMENTS);
        provider.getCredentials(Credentials.class, job, ACL.SYSTEM);

        assertEquals("both Item overloads must reach the filter", 2, provider.seenItemGroups.size());
        for (Object itemGroup : provider.seenItemGroups) {
            assertTrue(
                    "a top-level job's context is the Jenkins root, so a SYSTEM credential must not be"
                            + " filtered out, but the filter saw " + itemGroup,
                    itemGroup instanceof Jenkins);
        }
    }

    @Test
    public void aNestedJobResolvesToItsFolderSoSystemCredentialsStayHidden() throws Exception {
        MockFolder folder = jenkins.createFolder("team");
        FreeStyleProject job = folder.createProject(FreeStyleProject.class, "nested");
        RecordingProvider provider = new RecordingProvider();

        provider.getCredentials(Credentials.class, job, ACL.SYSTEM, NO_REQUIREMENTS);

        assertEquals(1, provider.seenItemGroups.size());
        assertSame(folder, provider.seenItemGroups.get(0));
        assertFalse(
                "a folder is not the Jenkins root, so SYSTEM credentials must still be filtered out here",
                provider.seenItemGroups.get(0) instanceof Jenkins);
    }

    @Test
    public void anItemThatIsItselfAnItemGroupResolvesToItself() throws Exception {
        // The base class resolves an item to itself when it is also an item group. Delegating on
        // getParent() alone would hand the filter the folder's own parent — the Jenkins root — and so
        // would widen SYSTEM visibility to a context that is not the root.
        MockFolder folder = jenkins.createFolder("team");
        RecordingProvider provider = new RecordingProvider();

        provider.getCredentials(Credentials.class, (Item) folder, ACL.SYSTEM, NO_REQUIREMENTS);

        assertEquals(1, provider.seenItemGroups.size());
        assertSame(folder, provider.seenItemGroups.get(0));
    }

    /** Records the item group the SYSTEM-scope filter actually sees, then runs the real filter. */
    private static final class RecordingProvider extends KmsCredentialsProvider {

        private final List<Object> seenItemGroups = new ArrayList<>();

        @Override
        public <C extends Credentials> List<C> getCredentials(
                Class<C> type,
                ItemGroup itemGroup,
                Authentication authentication,
                List<DomainRequirement> domainRequirements) {
            seenItemGroups.add(itemGroup);
            return super.getCredentials(type, itemGroup, authentication, domainRequirements);
        }
    }
}
