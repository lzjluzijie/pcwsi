package anonymous.research.pcws;

import static anonymous.research.pcws.ZpHash.add;
import static anonymous.research.pcws.ZpHash.sub;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.gf2k.Gf2kDokvsFactory.Gf2kDokvsType;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.hashbin.object.HashBinEntry;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBin;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkUtils;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.BlockUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.opf.oprf.MpOprfConfig;
import edu.alibaba.mpc4j.s2pc.opf.oprf.MpOprfReceiver;
import edu.alibaba.mpc4j.s2pc.opf.oprf.MpOprfReceiverOutput;
import edu.alibaba.mpc4j.s2pc.opf.oprf.MpOprfSender;
import edu.alibaba.mpc4j.s2pc.opf.oprf.MpOprfSenderOutput;
import edu.alibaba.mpc4j.s2pc.opf.oprf.OprfFactory;
import edu.alibaba.mpc4j.s2pc.opf.oprf.rs21.Rs21MpOprfConfig;

/**
 * Two-party PC-WSI based on anonymous offset lookup, semi-honest.
 * <p>
 * Inputs: P1 holds m distinct items x_i with values u_i, and P2 holds m distinct items y_j with values v_j, all values
 * in Z_p. Output: P1 gets w with w_j = u_i + v_j mod p if y_j = x_i for some i, and null otherwise, in P2's order.
 * Every such sum must be below M.
 * <p>
 * N = ⌈1.27m⌉ cuckoo bins with three hash functions h_t and no stash; p is the smallest prime above 3mNM·2^λ. F is
 * mpc4j's RS21 multi-point OPRF over the binary clustered blaze OKVS of RR22, and H hashes its 16-byte outputs to Z_p.
 * <p>
 * Offline (independent of the inputs): both parties initialize the OPRF and PS, and run the PS offline phase on a
 * random permutation π chosen by P2.
 * <p>
 * Online:
 * <ol>
 *   <li>P1 inserts its items into the cuckoo table and sends the hash keys to P2.</li>
 *   <li>OPRF with P1 as receiver: for each item x stored in bin s by h_t, P1 gets F(x‖t).</li>
 *   <li>P1 sets z_s = u + H(F(x‖t)) for that bin, and a random z_s for each empty bin.</li>
 *   <li>PS online on z: P1 gets a and P2 gets b with a[π(s)] + b[π(s)] = z_s.</li>
 *   <li>P2 sends c_{j,t} = b[π(h_t(y_j))] + v_j - H(F(y_j‖t)) for t = 1, 2, 3, each triple in random order, in the order
 *   of its items.</li>
 *   <li>P1 finds the pairs (i, l) with a_i + c_{j,l} mod p < M by binary search over the sorted a. If there is exactly
 *   one, w_j is that sum; otherwise w_j is null.</li>
 * </ol>
 * Each offline run serves one online run.
 */
public class OffsetLookup {
    private static final CuckooHashBinType CUCKOO_TYPE = CuckooHashBinType.NO_STASH_PSZ18_3_HASH;
    private static final int HASH_NUM = CuckooHashBinFactory.getHashNum(CUCKOO_TYPE);
    // Tweak of H, distinct from the layer tweaks of PermuteShare
    private static final int OPRF_TWEAK = -1;

    private OffsetLookup() {
        // empty
    }

    private enum PtoStep {
        P1_SEND_HASH_KEYS,
        P2_SEND_CANDIDATES,
    }

    /**
     * Number of cuckoo bins N for m items.
     */
    public static int binNum(int size) {
        return CuckooHashBinFactory.getBinNum(CUCKOO_TYPE, size);
    }

    /**
     * The smallest prime above 3mNM·2^λ.
     */
    public static BigInteger prime(int size, BigInteger upperBoundM) {
        return BigInteger.valueOf(3L * size * binNum(size)).multiply(upperBoundM)
                .shiftLeft(CommonConstants.STATS_BIT_LENGTH).nextProbablePrime();
    }

    /**
     * Configuration shared by both parties.
     */
    public static class Config extends AbstractMultiPartyPtoConfig {
        private final MpOprfConfig oprfConfig;
        private final PermuteShare.Config psConfig;

        /**
         * @param silent whether PS takes its correlated OTs from silent OT extension instead of IKNP.
         */
        public Config(boolean silent) {
            this(new Rs21MpOprfConfig.Builder(SecurityModel.SEMI_HONEST)
                    .setOkvsType(Gf2kDokvsType.H3_CLUSTER_BINARY_BLAZE_GCT).build(), new PermuteShare.Config(silent));
        }

        private Config(MpOprfConfig oprfConfig, PermuteShare.Config psConfig) {
            super(SecurityModel.SEMI_HONEST, oprfConfig, psConfig);
            this.oprfConfig = oprfConfig;
            this.psConfig = psConfig;
        }
    }

    /**
     * The party that learns the weight sums.
     */
    public static class P1 extends AbstractTwoPartyPto {
        private final MpOprfReceiver oprfReceiver;
        private final PermuteShare.Sender psSender;
        private int size;
        private int binNum;
        private BigInteger p;
        private BigInteger upperBoundM;
        private int byteLength;
        private ZpHash zpHash;
        private boolean prepared;

        public P1(Rpc rpc, Party p2, Config config) {
            super(OffsetLookupPtoDesc.getInstance(), rpc, p2, config);
            oprfReceiver = OprfFactory.createMpOprfReceiver(rpc, p2, config.oprfConfig);
            addSubPto(oprfReceiver);
            psSender = new PermuteShare.Sender(rpc, p2, config.psConfig);
            addSubPto(psSender);
        }

        public void init(int size, BigInteger upperBoundM) throws MpcAbortException {
            this.size = size;
            this.upperBoundM = upperBoundM;
            binNum = binNum(size);
            p = prime(size, upperBoundM);
            byteLength = CommonUtils.getByteLength(p.bitLength());
            zpHash = new ZpHash(p);
            oprfReceiver.init(size);
            psSender.init(p);
            initState();
        }

        public BigInteger getPrime() {
            return p;
        }

        public void offline() throws MpcAbortException {
            checkInitialized();
            psSender.offline(binNum);
            prepared = true;
        }

        /**
         * Returns w in P2's order, consuming the offline correlation.
         */
        public BigInteger[] online(byte[][] items, BigInteger[] values) throws MpcAbortException {
            checkInitialized();
            checkInputs(items, values, size, p);
            if (!prepared) {
                throw new IllegalStateException("offline() must run before each online()");
            }
            prepared = false;
            // The cuckoo table stores these objects themselves, and rejects duplicate items
            Map<ByteBuffer, Integer> indexOf = new IdentityHashMap<>(size);
            List<ByteBuffer> itemList = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
                ByteBuffer item = ByteBuffer.wrap(items[i]);
                indexOf.put(item, i);
                itemList.add(item);
            }

            // Step 1: insertion is retried with fresh keys until it succeeds
            CuckooHashBin<ByteBuffer> table = CuckooHashBinFactory.createEnforceNoStashCuckooHashBin(envType,
                    CUCKOO_TYPE, size, itemList, secureRandom);
            sendOtherPartyPayload(PtoStep.P1_SEND_HASH_KEYS.ordinal(), Arrays.asList(table.getHashKeys()));

            // Step 2
            int[] bins = new int[size];
            byte[][] oprfInputs = new byte[size][];
            int k = 0;
            for (int s = 0; s < binNum; s++) {
                HashBinEntry<ByteBuffer> entry = table.getHashBinEntry(s);
                if (entry != null) {
                    bins[k] = s;
                    oprfInputs[k] = oprfInput(entry.getItem().array(), entry.getHashIndex());
                    k++;
                }
            }
            MpOprfReceiverOutput oprfOutput = oprfReceiver.oprf(oprfInputs);

            // Step 3
            byte[][] prfs = new byte[size][];
            for (k = 0; k < size; k++) {
                prfs[k] = oprfOutput.getPrf(k);
            }
            BigInteger[] masks = zpHash.hashByValue(OPRF_TWEAK, prfs);
            BigInteger[] z = new BigInteger[binNum];
            for (k = 0; k < size; k++) {
                ByteBuffer item = table.getHashBinEntry(bins[k]).getItem();
                z[bins[k]] = add(values[indexOf.get(item)], masks[k], p);
            }
            for (int s = 0; s < binNum; s++) {
                if (z[s] == null) {
                    z[s] = BigIntegerUtils.randomNonNegative(p, secureRandom);
                }
            }

            // Step 4, then sorting a while P2 computes the candidates
            Range range = new Range(psSender.online(z), p);

            // Steps 5 and 6
            BigInteger[] candidates = receiveOtherPartyEqualSizePayload(PtoStep.P2_SEND_CANDIDATES.ordinal(),
                    HASH_NUM * size, byteLength).stream().map(BigIntegerUtils::byteArrayToNonNegBigInteger)
                    .toArray(BigInteger[]::new);
            return lookup(range, candidates, upperBoundM);
        }
    }

    /**
     * The party whose item order the output follows.
     */
    public static class P2 extends AbstractTwoPartyPto {
        private final MpOprfSender oprfSender;
        private final PermuteShare.Receiver psReceiver;
        private int size;
        private int binNum;
        private BigInteger p;
        private int byteLength;
        private ZpHash zpHash;
        // Permutation of the next online run, pi[s] = π(s)
        private int[] pi;

        public P2(Rpc rpc, Party p1, Config config) {
            super(OffsetLookupPtoDesc.getInstance(), rpc, p1, config);
            oprfSender = OprfFactory.createMpOprfSender(rpc, p1, config.oprfConfig);
            addSubPto(oprfSender);
            psReceiver = new PermuteShare.Receiver(rpc, p1, config.psConfig);
            addSubPto(psReceiver);
        }

        public void init(int size, BigInteger upperBoundM) throws MpcAbortException {
            this.size = size;
            binNum = binNum(size);
            p = prime(size, upperBoundM);
            byteLength = CommonUtils.getByteLength(p.bitLength());
            zpHash = new ZpHash(p);
            oprfSender.init(size);
            psReceiver.init(p);
            initState();
        }

        public BigInteger getPrime() {
            return p;
        }

        public void offline() throws MpcAbortException {
            checkInitialized();
            pi = PermutationNetworkUtils.randomPermutation(binNum, secureRandom);
            psReceiver.offline(pi);
        }

        public void online(byte[][] items, BigInteger[] values) throws MpcAbortException {
            checkInitialized();
            checkInputs(items, values, size, p);
            if (pi == null) {
                throw new IllegalStateException("offline() must run before each online()");
            }
            List<byte[]> hashKeys = receiveOtherPartyPayload(PtoStep.P1_SEND_HASH_KEYS.ordinal());
            MathPreconditions.checkEqual("hashKeys.size()", "hashNum", hashKeys.size(), HASH_NUM);
            // bins[t][j] = h_t(y_j), as P1's cuckoo table computes it
            int[][] bins = hashKeys.stream().map(key -> AesPrf.getIntegers(key, items, binNum)).toArray(int[][]::new);

            MpOprfSenderOutput oprfOutput = oprfSender.oprf(size);
            byte[][] prfs = new byte[HASH_NUM * size][];
            for (int j = 0; j < size; j++) {
                for (int t = 0; t < HASH_NUM; t++) {
                    prfs[HASH_NUM * j + t] = oprfOutput.getPrf(oprfInput(items[j], t));
                }
            }
            BigInteger[] masks = zpHash.hashByValue(OPRF_TWEAK, prfs);

            BigInteger[] b = psReceiver.online();
            // The order of each triple comes from a PRG seeded with fresh randomness
            SecureRandom coins = CommonUtils.createSeedSecureRandom();
            coins.setSeed(BlockUtils.randomBlock(secureRandom));
            List<byte[]> candidates = new ArrayList<>(HASH_NUM * size);
            for (int j = 0; j < size; j++) {
                for (int t : PermutationNetworkUtils.randomPermutation(HASH_NUM, coins)) {
                    BigInteger c = add(sub(b[pi[bins[t][j]]], masks[HASH_NUM * j + t], p), values[j], p);
                    candidates.add(BigIntegerUtils.nonNegBigIntegerToByteArray(c, byteLength));
                }
            }
            pi = null;
            sendOtherPartyEqualSizePayload(PtoStep.P2_SEND_CANDIDATES.ordinal(), candidates);
        }
    }

    /**
     * Step 6: w_j is a_i + c_{j,l} mod p if exactly one pair (i, l) gives a sum below M, and null otherwise.
     * candidates holds the three c_{j,l} of each j in turn.
     */
    static BigInteger[] lookup(BigInteger[] a, BigInteger[] candidates, BigInteger p, BigInteger upperBoundM) {
        return lookup(new Range(a, p), candidates, upperBoundM);
    }

    private static BigInteger[] lookup(Range range, BigInteger[] candidates, BigInteger upperBoundM) {
        BigInteger p = range.p;
        BigInteger[] w = new BigInteger[candidates.length / HASH_NUM];
        for (int j = 0; j < w.length; j++) {
            range.reset();
            for (int l = 0; l < HASH_NUM && range.hits < 2; l++) {
                BigInteger c = candidates[HASH_NUM * j + l];
                // a_i + c mod p < M  ⇔  a_i ∈ [lo, lo + M) mod p with lo = -c mod p; the range wraps past p
                BigInteger lo = c.signum() == 0 ? BigInteger.ZERO : p.subtract(c);
                BigInteger hi = lo.add(upperBoundM);
                range.scan(lo, hi.min(p), c);
                if (hi.compareTo(p) > 0) {
                    range.scan(BigInteger.ZERO, hi.subtract(p), c);
                }
            }
            w[j] = range.hits == 1 ? range.sum : null;
        }
        return w;
    }

    /**
     * The sorted a_i, searched by their top 63 bits as longs and then compared exactly.
     */
    private static final class Range {
        private final BigInteger p;
        private final BigInteger[] sorted;
        private final long[] keys;
        private final int shift;
        private int hits;
        private BigInteger sum;

        Range(BigInteger[] a, BigInteger p) {
            this.p = p;
            sorted = a.clone();
            Arrays.sort(sorted);
            shift = Math.max(0, p.bitLength() - (Long.SIZE - 1));
            keys = Arrays.stream(sorted).mapToLong(ai -> ai.shiftRight(shift).longValue()).toArray();
        }

        void reset() {
            hits = 0;
            sum = null;
        }

        /**
         * Counts the a_i in [lo, hi), up to two, and records a_i + c mod p for the last one.
         */
        void scan(BigInteger lo, BigInteger hi, BigInteger c) {
            long keyHi = hi.subtract(BigInteger.ONE).shiftRight(shift).longValue();
            for (int i = lowerBound(lo.shiftRight(shift).longValue()); i < keys.length && keys[i] <= keyHi && hits < 2;
                 i++) {
                if (sorted[i].compareTo(lo) >= 0 && sorted[i].compareTo(hi) < 0) {
                    hits++;
                    sum = add(sorted[i], c, p);
                }
            }
        }

        /**
         * The first index i with keys[i] ≥ key.
         */
        private int lowerBound(long key) {
            int lo = 0;
            int hi = keys.length;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (keys[mid] < key) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }
    }

    /**
     * OPRF input x‖t, with t as one trailing byte.
     */
    private static byte[] oprfInput(byte[] item, int hashIndex) {
        byte[] input = Arrays.copyOf(item, item.length + 1);
        input[item.length] = (byte) hashIndex;
        return input;
    }

    private static void checkInputs(byte[][] items, BigInteger[] values, int size, BigInteger p) {
        MathPreconditions.checkEqual("items.length", "size", items.length, size);
        MathPreconditions.checkEqual("values.length", "size", values.length, size);
        for (BigInteger value : values) {
            if (value.signum() < 0 || value.compareTo(p) >= 0) {
                throw new IllegalArgumentException("Values must be in [0, p)");
            }
        }
    }

    /**
     * Protocol description
     */
    private static class OffsetLookupPtoDesc implements PtoDesc {
        private static final int PTO_ID = 0x20261026;
        private static final String PTO_NAME = "PCWS_OFFSET_LOOKUP";
        private static final OffsetLookupPtoDesc INSTANCE = new OffsetLookupPtoDesc();

        private OffsetLookupPtoDesc() {
            // empty
        }

        static PtoDesc getInstance() {
            return INSTANCE;
        }

        static {
            PtoDescManager.registerPtoDesc(getInstance());
        }

        @Override
        public int getPtoId() {
            return PTO_ID;
        }

        @Override
        public String getPtoName() {
            return PTO_NAME;
        }
    }
}
