package anonymous.research.pcws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;

import org.junit.Test;

import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.tcrhf.Tcrhf;
import edu.alibaba.mpc4j.common.tool.crypto.tcrhf.TcrhfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.tcrhf.TcrhfFactory.TcrhfType;
import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkUtils;
import edu.alibaba.mpc4j.common.tool.utils.BlockUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

/**
 * Checks PermuteShare against the F_PS functionality: a[π(i)] + b[π(i)] = z[i] in Z_p, with a uniform. Also checks
 * that its batched hash matches mpc4j's TMMO block for block.
 */
public class PermuteShareTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    // Two-party prime sizes: 61 bits (one hash block), about 3mNM·2^λ for m = 2^20 (two blocks), and 220 bits
    private static final BigInteger[] PRIMES = {
            BigInteger.ONE.shiftLeft(61).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(102).nextProbablePrime(),
            BigInteger.ONE.shiftLeft(220).nextProbablePrime(),
    };

    @Test
    public void testSizes() throws Exception {
        for (int num : new int[]{2, 3, 4, 5, 7, 8, 9, 16, 33, 1000, 1025}) {
            int[] pi = PermutationNetworkUtils.randomPermutation(num, RANDOM);
            check(new PermuteShare.Config(false), PRIMES[1], new int[][]{pi});
        }
    }

    @Test
    public void testPrimes() throws Exception {
        for (BigInteger p : PRIMES) {
            check(new PermuteShare.Config(false), p, new int[][]{PermutationNetworkUtils.randomPermutation(257, RANDOM)});
        }
    }

    @Test
    public void testFixedPermutations() throws Exception {
        int num = 100;
        int[] identity = IntStream.range(0, num).toArray();
        int[] reverse = IntStream.range(0, num).map(i -> num - 1 - i).toArray();
        check(new PermuteShare.Config(false), PRIMES[1], new int[][]{identity, reverse});
    }

    @Test
    public void testRepeatedRuns() throws Exception {
        int[][] pis = IntStream.range(0, 3).mapToObj(r -> PermutationNetworkUtils.randomPermutation(64, RANDOM))
                .toArray(int[][]::new);
        check(new PermuteShare.Config(false), PRIMES[1], pis);
    }

    @Test
    public void testSilentCot() throws Exception {
        check(new PermuteShare.Config(true), PRIMES[1], new int[][]{PermutationNetworkUtils.randomPermutation(4097, RANDOM)});
    }

    @Test
    public void testHashMatchesTmmo() {
        Tcrhf tmmo = TcrhfFactory.createInstance(EnvType.STANDARD, TcrhfType.TMMO);
        int layer = 5;
        byte[][] xs = IntStream.range(0, 100).mapToObj(s -> BlockUtils.randomBlock(RANDOM)).toArray(byte[][]::new);
        for (BigInteger p : PRIMES) {
            int byteLength = Integer.BYTES * CommonUtils.getUnitNum(p.bitLength() + CommonConstants.STATS_BIT_LENGTH,
                    Integer.SIZE);
            int blocks = CommonUtils.getUnitNum(byteLength, CommonConstants.BLOCK_BYTE_LENGTH);
            BigInteger[] hashes = new ZpHash(p).hash(layer, xs);
            for (int s = 0; s < xs.length; s++) {
                byte[] bytes = new byte[blocks * CommonConstants.BLOCK_BYTE_LENGTH];
                for (int j = 0; j < blocks; j++) {
                    System.arraycopy(tmmo.hash(layer, s * blocks + j, xs[s]), 0, bytes,
                            j * CommonConstants.BLOCK_BYTE_LENGTH, CommonConstants.BLOCK_BYTE_LENGTH);
                }
                BigInteger y = new BigInteger(1, Arrays.copyOf(bytes, byteLength));
                assertEquals(y.multiply(p).shiftRight(Byte.SIZE * byteLength), hashes[s]);
                assertTrue(hashes[s].signum() >= 0 && hashes[s].compareTo(p) < 0);
            }
        }
    }

    /**
     * Runs one offline/online pair per permutation on fresh random inputs and checks the F_PS relation.
     */
    private static void check(PermuteShare.Config config, BigInteger p, int[][] pis) throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        Rpc senderRpc = rpcManager.getRpc(0);
        Rpc receiverRpc = rpcManager.getRpc(1);
        PermuteShare.Sender sender = new PermuteShare.Sender(senderRpc, receiverRpc.ownParty(), config);
        PermuteShare.Receiver receiver = new PermuteShare.Receiver(receiverRpc, senderRpc.ownParty(), config);
        BigInteger[][] zs = new BigInteger[pis.length][];
        for (int r = 0; r < pis.length; r++) {
            zs[r] = IntStream.range(0, pis[r].length).mapToObj(i -> new BigInteger(p.bitLength() + 40, RANDOM).mod(p))
                    .toArray(BigInteger[]::new);
        }

        CompletableFuture<BigInteger[][]> senderRun = CompletableFuture.supplyAsync(() -> {
            try {
                sender.init(p);
                BigInteger[][] as = new BigInteger[pis.length][];
                for (int r = 0; r < pis.length; r++) {
                    sender.offline(pis[r].length);
                    as[r] = sender.online(zs[r]);
                }
                return as;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        receiver.init(p);
        BigInteger[][] bs = new BigInteger[pis.length][];
        for (int r = 0; r < pis.length; r++) {
            receiver.offline(pis[r]);
            bs[r] = receiver.online();
        }
        BigInteger[][] as = senderRun.get();

        for (int r = 0; r < pis.length; r++) {
            int num = pis[r].length;
            BigInteger[] reconstructed = new BigInteger[num];
            for (int i = 0; i < num; i++) {
                BigInteger a = as[r][pis[r][i]];
                BigInteger b = bs[r][pis[r][i]];
                assertTrue(a.signum() >= 0 && a.compareTo(p) < 0);
                assertTrue(b.signum() >= 0 && b.compareTo(p) < 0);
                reconstructed[i] = a.add(b).mod(p);
            }
            assertArrayEquals(zs[r], reconstructed);
            // a is masked: with N >= 2 and |p| >= 61 bits, a[π(i)] = z[i] for every i only with negligible probability
            int round = r;
            assertNotEquals(0, IntStream.range(0, num).filter(i -> !as[round][pis[round][i]].equals(zs[round][i])).count());
        }
    }
}
