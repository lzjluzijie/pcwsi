package anonymous.research.pcws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;

import org.junit.Test;

import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;

/**
 * Checks OffsetLookup against the two-party PC-WSI functionality: for each item of P2 in order, P1 gets the weight
 * sum if P1 holds the item and null otherwise. Also checks the interval lookup against brute force.
 */
public class OffsetLookupTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger M = BigInteger.valueOf(1_000_000);

    @Test
    public void testSizes() throws Exception {
        for (int size : new int[]{1, 2, 3, 5, 16, 100, 1000}) {
            check(new OffsetLookup.Config(false), size, size / 2, 1, false);
        }
    }

    @Test
    public void testIntersectionSizes() throws Exception {
        check(new OffsetLookup.Config(false), 200, 0, 1, false);
        check(new OffsetLookup.Config(false), 200, 200, 1, false);
    }

    @Test
    public void testResidueValues() throws Exception {
        check(new OffsetLookup.Config(false), 500, 250, 1, true);
    }

    @Test
    public void testRepeatedRuns() throws Exception {
        check(new OffsetLookup.Config(false), 300, 100, 3, false);
    }

    @Test
    public void testSilentCot() throws Exception {
        check(new OffsetLookup.Config(true), 4096, 1000, 1, false);
    }

    /**
     * Small p and M, so many pairs pass the test and the ranges [lo, lo + M) often wrap past p.
     */
    @Test
    public void testLookupSmallPrime() {
        BigInteger p = BigInteger.valueOf(1009);
        for (int upperBound : new int[]{1, 2, 10, 100}) {
            for (int trial = 0; trial < 20; trial++) {
                BigInteger[] a = IntStream.range(0, 30).mapToObj(i -> BigInteger.valueOf(RANDOM.nextInt(1009)))
                        .toArray(BigInteger[]::new);
                BigInteger[] candidates = IntStream.range(0, 3 * 40)
                        .mapToObj(i -> BigInteger.valueOf(RANDOM.nextInt(1009))).toArray(BigInteger[]::new);
                // Force a few edge values: c = 0, c = 1 and c = p - 1
                candidates[0] = BigInteger.ZERO;
                candidates[1] = BigInteger.ONE;
                candidates[2] = p.subtract(BigInteger.ONE);
                checkLookup(a, candidates, p, BigInteger.valueOf(upperBound));
            }
        }
    }

    /**
     * Two-party prime size, so the search uses truncated keys. Candidates are placed at offsets around [0, M) from
     * chosen a_i, including ranges that wrap past p, and some a_i are close together.
     */
    @Test
    public void testLookupLargePrime() {
        BigInteger p = OffsetLookup.prime(1 << 20, M);
        for (int trial = 0; trial < 20; trial++) {
            BigInteger[] a = IntStream.range(0, 30).mapToObj(i -> new BigInteger(p.bitLength() + 40, RANDOM).mod(p))
                    .toArray(BigInteger[]::new);
            a[1] = BigInteger.ZERO;
            a[2] = p.subtract(BigInteger.ONE);
            a[3] = a[4].add(BigInteger.valueOf(RANDOM.nextInt(1_000_000))).mod(p);
            long[] offsets = {0, 1, 999_999, 1_000_000, -1, -1_000_000, 2_000_000};
            BigInteger[] candidates = IntStream.range(0, 3 * 60).mapToObj(i -> {
                if (i % 4 == 3) {
                    return new BigInteger(p.bitLength() + 40, RANDOM).mod(p);
                }
                BigInteger offset = BigInteger.valueOf(offsets[RANDOM.nextInt(offsets.length)]);
                return offset.subtract(a[RANDOM.nextInt(a.length)]).mod(p);
            }).toArray(BigInteger[]::new);
            checkLookup(a, candidates, p, M);
        }
    }

    private static void checkLookup(BigInteger[] a, BigInteger[] candidates, BigInteger p, BigInteger upperBoundM) {
        BigInteger[] expected = new BigInteger[candidates.length / 3];
        for (int j = 0; j < expected.length; j++) {
            int hits = 0;
            for (int l = 0; l < 3; l++) {
                for (BigInteger ai : a) {
                    BigInteger sum = ai.add(candidates[3 * j + l]).mod(p);
                    if (sum.compareTo(upperBoundM) < 0) {
                        hits++;
                        expected[j] = sum;
                    }
                }
            }
            if (hits != 1) {
                expected[j] = null;
            }
        }
        assertArrayEquals(expected, OffsetLookup.lookup(a, candidates, p, upperBoundM));
    }

    /**
     * Runs the protocol on fresh inputs of the given size sharing the given number of items and compares P1's output
     * with the ideal one. Weights are uniform in [0, M/2), so every sum is below M. With residues, the values are
     * instead uniform in Z_p subject to u + v mod p being such a sum, as after the reduction.
     */
    private static void check(OffsetLookup.Config config, int size, int common, int runs, boolean residues)
            throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        Rpc p1Rpc = rpcManager.getRpc(0);
        Rpc p2Rpc = rpcManager.getRpc(1);
        OffsetLookup.P1 p1 = new OffsetLookup.P1(p1Rpc, p2Rpc.ownParty(), config);
        OffsetLookup.P2 p2 = new OffsetLookup.P2(p2Rpc, p1Rpc.ownParty(), config);
        BigInteger p = OffsetLookup.prime(size, M);

        byte[][][] xs = new byte[runs][][];
        byte[][][] ys = new byte[runs][][];
        BigInteger[][] us = new BigInteger[runs][];
        BigInteger[][] vs = new BigInteger[runs][];
        BigInteger[][] expected = new BigInteger[runs][];
        for (int r = 0; r < runs; r++) {
            byte[][] items = distinctItems(2 * size - common);
            xs[r] = new byte[size][];
            ys[r] = new byte[size][];
            us[r] = new BigInteger[size];
            vs[r] = new BigInteger[size];
            expected[r] = new BigInteger[size];
            // P1 holds items [0, size) and P2 holds items [size - common, 2 size - common), in shuffled order
            int[] p1Order = shuffled(size);
            int[] p2Order = shuffled(size);
            Map<ByteBuffer, BigInteger> p1Values = new HashMap<>();
            for (int i = 0; i < size; i++) {
                xs[r][p1Order[i]] = items[i];
                us[r][p1Order[i]] = weight();
                p1Values.put(ByteBuffer.wrap(items[i]), us[r][p1Order[i]]);
            }
            for (int j = 0; j < size; j++) {
                int k = p2Order[j];
                ys[r][k] = items[size - common + j];
                vs[r][k] = weight();
                BigInteger u = p1Values.get(ByteBuffer.wrap(ys[r][k]));
                expected[r][k] = u == null ? null : u.add(vs[r][k]);
            }
            if (residues) {
                // Each item gets a random shift, added by P1 and subtracted by P2
                Map<ByteBuffer, BigInteger> shifts = new HashMap<>();
                for (byte[] item : items) {
                    shifts.put(ByteBuffer.wrap(item), new BigInteger(p.bitLength() + 40, RANDOM).mod(p));
                }
                for (int i = 0; i < size; i++) {
                    us[r][i] = us[r][i].add(shifts.get(ByteBuffer.wrap(xs[r][i]))).mod(p);
                    vs[r][i] = vs[r][i].subtract(shifts.get(ByteBuffer.wrap(ys[r][i]))).mod(p);
                }
            }
        }

        CompletableFuture<Void> p2Run = CompletableFuture.runAsync(() -> {
            try {
                p2.init(size, M);
                for (int r = 0; r < runs; r++) {
                    p2.offline();
                    p2.online(ys[r], vs[r]);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        p1.init(size, M);
        assertEquals(p, p1.getPrime());
        for (int r = 0; r < runs; r++) {
            p1.offline();
            BigInteger[] w = p1.online(xs[r], us[r]);
            assertArrayEquals(expected[r], w);
        }
        p2Run.get();
    }

    private static byte[][] distinctItems(int num) {
        Set<ByteBuffer> seen = new HashSet<>();
        byte[][] items = new byte[num][];
        for (int i = 0; i < num; ) {
            byte[] item = new byte[1 + RANDOM.nextInt(16)];
            RANDOM.nextBytes(item);
            if (seen.add(ByteBuffer.wrap(item))) {
                items[i++] = item;
            }
        }
        return items;
    }

    private static int[] shuffled(int num) {
        int[] order = IntStream.range(0, num).toArray();
        for (int i = num - 1; i > 0; i--) {
            int k = RANDOM.nextInt(i + 1);
            int t = order[i];
            order[i] = order[k];
            order[k] = t;
        }
        return order;
    }

    private static BigInteger weight() {
        return BigInteger.valueOf(RANDOM.nextLong(M.longValueExact() / 2));
    }
}
