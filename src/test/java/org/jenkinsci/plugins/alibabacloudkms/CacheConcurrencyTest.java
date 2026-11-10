package org.jenkinsci.plugins.alibabacloudkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.DescribeSecretRequest;
import com.aliyun.kms20160120.models.DescribeSecretResponse;
import com.aliyun.kms20160120.models.ListSecretsRequest;
import com.aliyun.kms20160120.models.ListSecretsResponse;
import com.aliyun.kms20160120.models.ListSecretsResponseBody;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretList;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecret;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecretTags;
import com.aliyun.kms20160120.models.ListSecretsResponseBody.ListSecretsResponseBodySecretListSecretTagsTag;
import com.aliyun.teaopenapi.models.Config;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.LoadingCache;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.jenkinsci.plugins.alibabacloudkms.KmsCredentialsProvider.CredentialListCacheKey;
import org.jenkinsci.plugins.alibabacloudkms.KmsCredentialsProvider.SecretCacheKey;
import org.junit.Test;

/**
 * The discovery cache is a single entry shared by every credential lookup on the controller, so both
 * its timing and its behaviour under failure are load-bearing: a lookup that waits on KMS stalls page
 * renders and {@code withCredentials} alike.
 */
public class CacheConcurrencyTest {

    private static final CredentialListCacheKey KEY =
            CredentialListCacheKey.of("endpoint", "jenkins:credentials");

    /**
     * A blank endpoint fails inside the client factory before any socket is opened, which stands in for
     * an unreachable KMS without making the test depend on the network.
     */
    private static final CredentialListCacheKey UNREACHABLE =
            CredentialListCacheKey.of("", "jenkins:credentials");

    @Test
    public void validatesCacheSeconds() {
        assertEquals(0L, KmsGlobalConfiguration.validateCacheSeconds(0L));
        assertEquals(1L, KmsGlobalConfiguration.validateCacheSeconds(1L));
        assertEquals(300L, KmsGlobalConfiguration.validateCacheSeconds(300L));
        assertThrows(IllegalArgumentException.class, () -> KmsGlobalConfiguration.validateCacheSeconds(null));
        assertThrows(IllegalArgumentException.class, () -> KmsGlobalConfiguration.validateCacheSeconds(-1L));
    }

    @Test
    public void neverCachesWhenCacheSecondsIsZero() {
        Cache<String, String> cache = KmsCredentialsProvider.newCache(0L);
        AtomicInteger loads = new AtomicInteger();
        assertEquals("value-1", cache.get("key", ignored -> "value-" + loads.incrementAndGet()));
        assertEquals("value-2", cache.get("key", ignored -> "value-" + loads.incrementAndGet()));
        assertEquals(2, loads.get());
        assertNull(cache.getIfPresent("key"));
    }

    @Test
    public void parsesFlatRdsPayloadReturnedByGetSecretValue() {
        // GetSecretValue returns RDS as a flat object (the internal Version field is stripped
        // server-side); the {"Accounts":[...]} shape is only the CreateSecret input.
        KmsManagedSecretRetriever.Value value = KmsManagedSecretRetriever.parse(
                "rds-secret",
                "{\"AccountName\":\"database-user\",\"AccountPassword\":\"database-password\"}",
                ManagedSecretType.RDS);

        assertEquals("database-user", value.username());
        assertEquals("database-password", value.password());
    }

    @Test
    public void rejectsCreateInputAccountsShapeThatGetSecretValueNeverReturns() {
        assertThrows(
                KmsPluginException.class,
                () -> KmsManagedSecretRetriever.parse(
                        "rds-secret",
                        "{\"Accounts\":[{\"AccountName\":\"database-user\",\"AccountPassword\":\"database-password\"}]}",
                        ManagedSecretType.RDS));
    }

    @Test
    public void credentialListCacheReusesDiscoveryForThirtySeconds() throws Exception {
        AtomicLong now = new AtomicLong();
        CountingClient client = new CountingClient();
        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache =
                KmsCredentialsProvider.newCredentialListCache(countingLoader(client), now::get, Runnable::run);

        Map<String, IdCredentials> first = cache.get(KEY);
        assertSame("a lookup inside the window must not touch KMS again", first, cache.get(KEY));

        // Past the window the entry is reloaded. The direct executor runs that reload inline, but
        // Caffeine still hands the triggering lookup the previous list and exposes the reloaded content
        // to the next one; the refresh re-arms the window, so that second lookup costs no further call.
        // That readers are served the previous list while a reload is in flight is covered by the test
        // below, which uses a real executor.
        now.set(TimeUnit.SECONDS.toNanos(31));
        cache.get(KEY);
        Map<String, IdCredentials> tagChanged = cache.get(KEY);
        assertEquals("an elapsed window must cost exactly one reload", 2, client.listCalls.get());
        assertNotSame(
                "a mapping-tag change must produce a fresh credential object",
                first.get("credential"),
                tagChanged.get("credential"));

        // Past the hard expiry the entry is dropped, so this lookup blocks on a full load.
        now.set(TimeUnit.SECONDS.toNanos(400));
        Map<String, IdCredentials> reloaded = cache.get(KEY);
        assertEquals(3, client.listCalls.get());
        assertNotSame(
                "an updated secret must produce a fresh credential object",
                tagChanged.get("credential"),
                reloaded.get("credential"));

        assertEquals("listing must not describe each secret", 0, client.describeCalls.get());
        assertEquals(Arrays.asList(1, 1, 1), client.pageNumbers);
        assertThrows(UnsupportedOperationException.class, () -> first.put("other", first.get("credential")));
    }

    @Test
    public void refreshRunsInTheBackgroundSoReadersNeverWaitOnKms() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch releaseRefresh = new CountDownLatch(1);
        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache =
                KmsCredentialsProvider.newCredentialListCache(
                        gatedLoader(loads, 2, refreshStarted, releaseRefresh), now::get, ForkJoinPool.commonPool());

        Map<String, IdCredentials> first = cache.get(KEY);
        assertEquals(1, loads.get());

        now.set(TimeUnit.SECONDS.toNanos(31));
        assertSame("a reader must be served the previous list, not made to wait on KMS", first, cache.get(KEY));
        assertTrue("the reload must have been handed to the executor", refreshStarted.await(5, TimeUnit.SECONDS));

        assertSame("a reader arriving mid-reload must not queue behind it", first, cache.get(KEY));
        assertEquals("one discovery window must cost one reload, not one per reader", 2, loads.get());

        releaseRefresh.countDown();
        awaitReloaded(cache, first);
        assertEquals("reading the reloaded list must not trigger another reload", 2, loads.get());
    }

    @Test
    public void expiredEntryLoadsOnceForConcurrentReaders() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch secondLoadStarted = new CountDownLatch(1);
        CountDownLatch releaseSecondLoad = new CountDownLatch(1);
        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache =
                KmsCredentialsProvider.newCredentialListCache(
                        gatedLoader(loads, 2, secondLoadStarted, releaseSecondLoad),
                        now::get,
                        ForkJoinPool.commonPool());

        assertTrue(cache.get(KEY).isEmpty());
        assertEquals(1, loads.get());

        // Past the hard expiry there is nothing left to serve, so readers block again — on one load.
        now.set(TimeUnit.SECONDS.toNanos(301));
        ExecutorService executor = Executors.newFixedThreadPool(6);
        try {
            List<Future<Map<String, IdCredentials>>> readers = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                readers.add(executor.submit(() -> cache.get(KEY)));
            }
            assertTrue(secondLoadStarted.await(5, TimeUnit.SECONDS));
            releaseSecondLoad.countDown();
            Map<String, IdCredentials> reloaded = readers.get(0).get(5, TimeUnit.SECONDS);
            for (Future<Map<String, IdCredentials>> reader : readers) {
                assertSame(reloaded, reader.get(5, TimeUnit.SECONDS));
            }
            assertEquals(2, loads.get());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void failedLoadHandsBackTheFallbackRatherThanAnEmptyList() {
        Cache<SecretCacheKey, IdCredentials> credentialCache = KmsCredentialsProvider.newCache(300L);
        Map<String, IdCredentials> previous = emptyCredentialList();

        assertSame(
                "a failed refresh must return the previous list so that the cache keeps serving it",
                previous,
                KmsCredentialsProvider.loadCredentialList(UNREACHABLE, previous, credentialCache, 300L));
        assertTrue(
                "a failed first load must degrade to no credentials rather than throw",
                KmsCredentialsProvider.loadCredentialList(
                                UNREACHABLE, Collections.emptyMap(), KmsCredentialsProvider.newCache(300L), 300L)
                        .isEmpty());
    }

    @Test
    public void credentialListFailureIsCachedForTheDiscoveryWindow() {
        AtomicLong now = new AtomicLong();
        AtomicInteger loads = new AtomicInteger();
        Cache<SecretCacheKey, IdCredentials> credentialCache = KmsCredentialsProvider.newCache(300L);
        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache =
                KmsCredentialsProvider.newCredentialListCache(
                        key -> {
                            loads.incrementAndGet();
                            return KmsCredentialsProvider.loadCredentialList(
                                    key, emptyCredentialList(), credentialCache, 300L);
                        },
                        now::get,
                        Runnable::run);

        Map<String, IdCredentials> first = cache.get(UNREACHABLE);
        Map<String, IdCredentials> second = cache.get(UNREACHABLE);

        assertTrue("a failed load must degrade to no credentials rather than throw", first.isEmpty());
        assertSame("the failure must be served from the cache, not retried per lookup", first, second);
        assertEquals(
                "a KMS outage must be paid for once per discovery window, not once per credential lookup",
                1,
                loads.get());

        now.set(TimeUnit.SECONDS.toNanos(31));
        cache.get(UNREACHABLE);
        cache.get(UNREACHABLE);

        assertEquals("the failure must be retried once the discovery window elapses", 2, loads.get());
    }

    @Test
    public void failedRefreshRearmsTheDiscoveryWindow() {
        AtomicLong now = new AtomicLong();
        AtomicInteger loads = new AtomicInteger();
        // Stands in for a reload that fails: the production loader hands the current value back in that
        // case, and returning it must restart the window rather than leave it permanently elapsed.
        LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache =
                KmsCredentialsProvider.newCredentialListCache(
                        new CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>>() {
                            @Override
                            public Map<String, IdCredentials> load(CredentialListCacheKey key) {
                                loads.incrementAndGet();
                                return emptyCredentialList();
                            }

                            @Override
                            public Map<String, IdCredentials> reload(
                                    CredentialListCacheKey key, Map<String, IdCredentials> currentValue) {
                                loads.incrementAndGet();
                                return currentValue;
                            }
                        },
                        now::get,
                        Runnable::run);

        Map<String, IdCredentials> first = cache.get(KEY);
        now.set(TimeUnit.SECONDS.toNanos(31));
        assertSame(first, cache.get(KEY));
        assertSame(first, cache.get(KEY));
        assertSame(first, cache.get(KEY));

        assertEquals(
                "without a re-armed window every lookup for the rest of the outage would queue a reload",
                2,
                loads.get());
    }

    @Test
    public void managedReadFailureIsRememberedThenRetried() {
        AtomicLong now = new AtomicLong();
        AtomicInteger reads = new AtomicInteger();
        KmsManagedSecretRetriever retriever =
                new KmsManagedSecretRetriever(null, "test-secret", null, ManagedSecretType.RDS, 300L) {
                    @Override
                    long now() {
                        return now.get();
                    }

                    @Override
                    String retrieveSecret() {
                        if (reads.incrementAndGet() == 1) {
                            throw new KmsPluginException("KMS is unreachable");
                        }
                        return "{\"AccountName\":\"db-user\",\"AccountPassword\":\"db-password\"}";
                    }
                };

        KmsPluginException first = assertThrows(KmsPluginException.class, retriever::getUsername);
        for (int i = 0; i < 5; i++) {
            assertSame(
                    "an outage must be paid for once per window, not once per credential picker entry",
                    first,
                    assertThrows(KmsPluginException.class, retriever::getUsername));
        }
        assertEquals(1, reads.get());

        now.addAndGet(31_000L);
        assertEquals("db-user", retriever.getUsername());
        assertEquals("db-password", retriever.get().getPlainText());
        assertEquals("both halves must still come from the one retried read", 2, reads.get());
    }

    @Test
    public void managedPairLoadsOnceForConcurrentReaders() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch firstLoadStarted = new CountDownLatch(1);
        CountDownLatch releaseFirstLoad = new CountDownLatch(1);
        KmsManagedSecretRetriever retriever =
                new KmsManagedSecretRetriever(null, "test-secret", null, ManagedSecretType.RDS, 300L) {
                    @Override
                    String retrieveSecret() {
                        int load = loads.incrementAndGet();
                        if (load == 1) {
                            firstLoadStarted.countDown();
                            try {
                                assertTrue(releaseFirstLoad.await(5, TimeUnit.SECONDS));
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new AssertionError(e);
                            }
                        }
                        return "{\"AccountName\":\"user-" + load + "\",\"AccountPassword\":\"password-" + load + "\"}";
                    }
                };

        ExecutorService executor = Executors.newFixedThreadPool(6);
        try {
            List<Future<String>> readers = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                readers.add(executor.submit(retriever::getUsername));
            }
            assertTrue(firstLoadStarted.await(5, TimeUnit.SECONDS));
            releaseFirstLoad.countDown();
            for (Future<String> reader : readers) {
                assertEquals("user-1", reader.get(5, TimeUnit.SECONDS));
            }
            assertEquals("password-1", retriever.get().getPlainText());
            assertEquals(1, loads.get());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void plainValueIsCachedForTheConfiguredLifetime() {
        AtomicLong now = new AtomicLong();
        AtomicInteger reads = new AtomicInteger();
        KmsSecretRetriever retriever = new KmsSecretRetriever(null, "test-secret", null, 300L) {
            @Override
            long now() {
                return now.get();
            }

            @Override
            public String retrieveSecret() {
                return "value-" + reads.incrementAndGet();
            }
        };

        assertEquals("value-1", retriever.get().getPlainText());
        assertEquals("value-1", retriever.get().getPlainText());
        assertEquals("repeated reads within the lifetime must be served from the value cache", 1, reads.get());

        now.addAndGet(301_000L);
        assertEquals("value-2", retriever.get().getPlainText());
        assertEquals("the value must be re-read once the lifetime elapses", 2, reads.get());
    }

    @Test
    public void plainValueIsNeverCachedWhenLifetimeIsZero() {
        AtomicInteger reads = new AtomicInteger();
        KmsSecretRetriever retriever = new KmsSecretRetriever(null, "test-secret", null, 0L) {
            @Override
            public String retrieveSecret() {
                return "value-" + reads.incrementAndGet();
            }
        };

        assertEquals("value-1", retriever.get().getPlainText());
        assertEquals("value-2", retriever.get().getPlainText());
        assertEquals("a zero lifetime must read live every time", 2, reads.get());
    }

    @Test
    public void managedSuccessIsNeverCachedAtZeroLifetimeButTheFailureBreakerSurvives() {
        AtomicLong now = new AtomicLong();
        AtomicInteger reads = new AtomicInteger();
        KmsManagedSecretRetriever retriever =
                new KmsManagedSecretRetriever(null, "test-secret", null, ManagedSecretType.RDS, 0L) {
                    @Override
                    long now() {
                        return now.get();
                    }

                    @Override
                    String retrieveSecret() {
                        int read = reads.incrementAndGet();
                        if (read == 1) {
                            throw new KmsPluginException("KMS is unreachable");
                        }
                        return "{\"AccountName\":\"user-" + read + "\",\"AccountPassword\":\"password-" + read + "\"}";
                    }
                };

        assertThrows(KmsPluginException.class, retriever::getUsername);
        assertThrows(KmsPluginException.class, retriever::getUsername);
        assertEquals("the failure breaker must still hold at a zero lifetime", 1, reads.get());

        now.addAndGet(31_000L);
        assertEquals("user-2", retriever.getUsername());
        assertEquals("user-3", retriever.getUsername());
        assertEquals("a zero lifetime must re-read the pair on every success", 3, reads.get());
    }

    /** Distinct on every call, so that identity assertions can tell two loads of the same content apart. */
    private static Map<String, IdCredentials> emptyCredentialList() {
        return Collections.unmodifiableMap(new HashMap<>());
    }

    private static CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>> countingLoader(
            CountingClient client) {
        Cache<SecretCacheKey, IdCredentials> credentialCache = KmsCredentialsProvider.newCache(300L);
        return key -> {
            try {
                return KmsCredentialsProvider.fetchCredentials(
                        key.endpoint(), key.tagKey(), client, credentialCache, 300L);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        };
    }

    private static CacheLoader<CredentialListCacheKey, Map<String, IdCredentials>> gatedLoader(
            AtomicInteger loads, int gatedLoad, CountDownLatch started, CountDownLatch release) {
        return key -> {
            if (loads.incrementAndGet() == gatedLoad) {
                started.countDown();
                try {
                    assertTrue("the test never released the gated load", release.await(5, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(e);
                }
            }
            return emptyCredentialList();
        };
    }

    private static void awaitReloaded(
            LoadingCache<CredentialListCacheKey, Map<String, IdCredentials>> cache, Map<String, IdCredentials> previous)
            throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (cache.get(KEY) == previous) {
            if (System.nanoTime() > deadline) {
                fail("the background reload never became visible to readers");
            }
            Thread.sleep(10L);
        }
    }

    private static class CountingClient extends Client {

        private final AtomicInteger listCalls = new AtomicInteger();
        private final AtomicInteger describeCalls = new AtomicInteger();
        private final List<Integer> pageNumbers = new ArrayList<>();

        CountingClient() throws Exception {
            super(new Config().setEndpoint("http://localhost"));
        }

        @Override
        public ListSecretsResponse listSecrets(ListSecretsRequest request) {
            int call = listCalls.incrementAndGet();
            pageNumbers.add(request.getPageNumber());
            if (call == 2) {
                return listResponse("2026-09-09T00:00:00Z", "string");
            }
            if (call == 3) {
                return listResponse("2026-09-09T00:01:00Z", "string");
            }
            return listResponse("2026-09-09T00:00:00Z", null);
        }

        @Override
        public DescribeSecretResponse describeSecret(DescribeSecretRequest request) {
            describeCalls.incrementAndGet();
            return null;
        }
    }

    private static ListSecretsResponse listResponse(String updateTime, String type) {
        ListSecretsResponseBodySecretListSecret secret = new ListSecretsResponseBodySecretListSecret()
                .setSecretName("credential")
                .setSecretType("Generic")
                .setUpdateTime(updateTime);
        if (type != null) {
            secret.setTags(new ListSecretsResponseBodySecretListSecretTags()
                    .setTag(Collections.singletonList(new ListSecretsResponseBodySecretListSecretTagsTag()
                            .setTagKey("jenkins:credentials:type")
                            .setTagValue(type))));
        }
        return new ListSecretsResponse()
                .setBody(new ListSecretsResponseBody()
                        .setTotalCount(1)
                        .setSecretList(
                                new ListSecretsResponseBodySecretList().setSecret(Collections.singletonList(secret))));
    }
}
