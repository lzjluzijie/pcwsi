package anonymous.research.pcws;

import static edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory.HashType.JDK_SHA256;
import static anonymous.research.pcws.ZpHash.add;
import static anonymous.research.pcws.ZpHash.sub;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPto;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.SparseZpDokvs;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.ZpDokvsFactory;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.ZpDokvsFactory.ZpDokvsType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.Zp;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpFactory;
import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkUtils;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.common.tool.utils.LongUtils;

/**
 * PCWS (Private Computation Weighted Sum) Protocol Implementation
 * <p>
 * This protocol implements a multi-party computation for computing weighted sums
 * over key-value pairs with privacy preservation.
 */
public class Protocol extends AbstractMultiPartyPto {
    private static final Hash SHA256 = HashFactory.createInstance(JDK_SHA256, 32);
    private static final int STEP = 0;
    // Tweak of the hash that maps F_K to Z_p
    private static final int PRF_TWEAK = 0;
    // Appended to the input of F̃ to separate it from the tags F̂
    private static final byte[] TILDE_DOMAIN = {1};

    // Configuration
    private final Config config;
    private final TopologyType topologyType;
    private final ResultType resultType;

    // Protocol parameters
    private final int secLevel;        // Security parameter κ
    private final int statLevel;       // Statistical security parameter λ
    private final int parties;         // Number of parties n
    private final int size;            // Number of key-value pairs per party m
    private final int threshold;       // Threshold t for weighted sum
    private final BigInteger upperBoundM;  // Upper bound for weight sums M

    // Cryptographic components
    private final BigInteger p, q;     // Prime numbers
    private final ZpDokvsType zpDokvsType;
    private final Zp zP, zQ;
    private final int okvsSize;
    private final int pByteLength, qByteLength;  // fixed-width encodings of Z_p and Z_q elements
    private final SecureRandom secureRandom;
    private final ZpHash zpHash;
    // OKVS, always encoded doubly (free cells random) so that keys outside a table decode to random values. Each run
    // gets a fresh instance, dropped at the end of the reduction, because an instance keeps the intermediate
    // structures of its last encoding.
    private final byte[][] okvsKeys;
    private SparseZpDokvs<Long> okvs;
    private final OffsetLookup.Config lookupConfig;
    private Schedule schedule = Schedule.NONE;

    // Measurements of the current execute() call
    private final MeteredRpc meter;
    private long startNanos;
    private long waitNanosAtStart;
    private long recvBytesAtStart;
    private long sentBytesAtStart;
    private Phase reduction;
    private Phase offline;
    private Phase total;

    /**
     * Constructor
     */
    public Protocol(MeteredRpc rpc, Config config, Party... otherParties) {
        super(PcwsPtoDesc.getInstance(), config, rpc, otherParties);

        this.meter = rpc;
        this.config = config;
        this.topologyType = config.getTopologyType();
        this.resultType = config.getResultType();
        this.secLevel = config.getSecLevel();
        this.statLevel = config.getStatLevel();
        this.parties = config.getParties();
        this.size = config.getSize();
        this.threshold = config.getThreshold();
        this.upperBoundM = config.getUpperBoundM();
        this.p = config.getP();
        this.q = config.getQ();
        this.zP = ZpFactory.createInstance(envType, p);
        this.zQ = ZpFactory.createInstance(envType, q);
        this.zpDokvsType = config.getZpDokvsType();
        this.okvsSize = ZpDokvsFactory.getM(zpDokvsType, size);
        this.pByteLength = CommonUtils.getByteLength(p.bitLength());
        this.qByteLength = CommonUtils.getByteLength(q.bitLength());

        this.secureRandom = new SecureRandom();
        this.zpHash = new ZpHash(p);

        // Keys of the H3_SPARSE_CLUSTER_BLAZE_GCT OKVS
        this.okvsKeys = new byte[3][secLevel / 8]; // H3 requires 3 keys
        for (int i = 0; i < 3; i++) {
            okvsKeys[i][i] = (byte) i;
        }
        this.lookupConfig = new OffsetLookup.Config(config.isSilent());
    }

    public Config getConfig() {
        return config;
    }

    /**
     * Runs the reductions of the following execute() calls under the given schedule, see {@link Schedule}. Not for
     * the AIDED and LOOKUP topologies.
     */
    public void setSchedule(Schedule.Mode mode, Path dir) throws IOException {
        schedule = mode == Schedule.Mode.NONE ? Schedule.NONE
                : new Schedule(mode, dir, meter, topologyType, parties, okvsSize, p);
    }

    /**
     * Measurements of the reduction to two-party PC-WSI, which ends at the mod-q truncation (P1, P2) or after
     * forwarding the masked OKVS (P3-Pn). Empty for the AIDED and LOOKUP topologies.
     */
    public Phase getReduction() {
        return reduction;
    }

    /**
     * Measurements up to the end of the input-independent part of the two-party protocol: its initialization and
     * offline phase for LOOKUP. Equal to the reduction for the other two-party protocols and for P3-Pn.
     */
    public Phase getOffline() {
        return offline;
    }

    /**
     * Measurements of the whole execute() call.
     */
    public Phase getTotal() {
        return total;
    }

    /**
     * Main protocol execution
     *
     * @return for P1 with result type AIDED or LOOKUP, or topology AIDED or LOOKUP, the weight sums aligned with P2's
     * input order (null where the item is not in the intersection); otherwise null.
     */
    public BigInteger[] execute(KeyValuePair[] inputPairs) throws Exception {
        if (inputPairs != null) {
            for (KeyValuePair pair : inputPairs) {
                if (pair.value() < 0 || BigInteger.valueOf(pair.value()).compareTo(upperBoundM) >= 0) {
                    throw new IllegalArgumentException("Weights must be in [0, M)");
                }
            }
        }
        okvs = ZpDokvsFactory.createSparseInstance(envType, zpDokvsType, p, size, okvsKeys);
        startNanos = System.nanoTime();
        waitNanosAtStart = meter.getWaitNanos();
        recvBytesAtStart = meter.getReceivedByteLength();
        sentBytesAtStart = rpc.getPayloadByteLength();
        offline = null;
        schedule.begin();
        BigInteger[] output = switch (topologyType) {
            case STAR -> executeStar(inputPairs);
            case RING, TREE -> executeRing(inputPairs);
            case AIDED -> executeAided(inputPairs);
            case LOOKUP -> executeLookup(inputPairs);
        };
        total = snapshot();
        if (offline == null) {
            offline = reduction;
        }
        return output;
    }

    /**
     * Server-aided two-party PC-WSI on the raw inputs of P1 and P2, with P3 as the server.
     */
    public BigInteger[] executeAided(KeyValuePair[] inputPairs) {
        reduction = snapshot();
        int partyId = rpc.ownParty().getPartyId();
        if (partyId == 2) {
            runAidedServer();
            return null;
        }
        BigInteger[] keys = Arrays.stream(inputPairs).map(pair -> BigInteger.valueOf(pair.key()))
                                  .toArray(BigInteger[]::new);
        BigInteger[] values = Arrays.stream(inputPairs).map(pair -> BigInteger.valueOf(pair.value()))
                                    .toArray(BigInteger[]::new);
        if (partyId == 0) {
            return runAidedP1(keys, values);
        }
        runAidedP2(keys, values);
        return null;
    }

    /**
     * Offset-lookup two-party PC-WSI on the raw inputs of P1 and P2.
     */
    public BigInteger[] executeLookup(KeyValuePair[] inputPairs) throws Exception {
        reduction = snapshot();
        BigInteger[] keys = Arrays.stream(inputPairs).map(pair -> BigInteger.valueOf(pair.key()))
                                  .toArray(BigInteger[]::new);
        BigInteger[] values = Arrays.stream(inputPairs).map(pair -> BigInteger.valueOf(pair.value()))
                                    .toArray(BigInteger[]::new);
        if (rpc.ownParty().getPartyId() == 0) {
            return runLookupP1(keys, values);
        }
        runLookupP2(keys, values);
        return null;
    }

    /**
     * Star topology execution
     */
    public BigInteger[] executeStar(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        if (partyId == 0) {
            return runP1Star(inputPairs);
        } else if (partyId == 1) {
            runP2Star(inputPairs);
        } else {
            runPnStar(inputPairs);
        }
        return null;
    }

    /**
     * Ring and tree topology execution. Both use the double-layered masks and differ only in routing.
     */
    public BigInteger[] executeRing(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        if (partyId == 0) {
            return runP1Ring(inputPairs);
        } else if (partyId == 1) {
            runP2Ring(inputPairs);
        } else {
            runPnRing(inputPairs);
        }
        return null;
    }

    /**
     * P1's protocol execution - Star topology
     */
    public BigInteger[] runP1Star(KeyValuePair[] inputPairs) throws Exception {
        // P1 computes T = sum_{i=2}^{n} T_i' and U = {u_j | u_j = Decode(T, x_{1,j}), j ∈ [m]}
        schedule.awaitTurn();
        BigInteger[] okvsData = new BigInteger[okvsSize];
        Arrays.fill(okvsData, BigInteger.ZERO);
        addReceived(okvsData, IntStream.range(1, parties).toArray());

        // Decode U = {u_j | u_j = Decode(T, x_{1,j}), j ∈ [m]}
        BigInteger[] U = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            U[i] = okvs.decode(okvsData, inputPairs[i].key());
        }
        return truncateP1(U, inputPairs);
    }

    /**
     * P2's protocol execution - Star topology
     */
    public void runP2Star(KeyValuePair[] inputPairs) throws Exception {
        byte[] prfKey = new byte[secLevel / 8];
        secureRandom.nextBytes(prfKey);

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), prfKey);
        }

        byte[][] seeds = new byte[parties - 2][secLevel / 8];
        for (int i = 0; i < seeds.length; i++) {
            secureRandom.nextBytes(seeds[i]);
        }

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), seeds[k - 2]);
        }

        schedule.awaitTurn();
        BigInteger[] p2Random = new BigInteger[size];
        BigInteger[] okvsData = schedule.local(() -> {
            BigInteger[] data = okvs.encode(p2KeyValueMap(prfKey, inputPairs, p2Random), true);
            // Masked OKVS T_2' = T_2 + Γ_2, where Γ_2 = -sum_{i=3}^{n} G(s_i)
            for (byte[] seed : seeds) {
                addPrgVector(data, seed, true);
            }
            return data;
        });

        sendBigIntegerArray(STEP, rpc.getParty(0), okvsData, pByteLength);
        truncateP2(p2Random);
    }

    /**
     * P3-Pn parties' protocol execution - Star topology
     */
    public void runPnStar(KeyValuePair[] inputPairs) throws Exception {
        byte[] prfKey = receiveByteArray(STEP,
                rpc.getParty(1));

        byte[] seed = receiveByteArray(STEP,
                rpc.getParty(1));

        schedule.awaitTurn();
        BigInteger[] okvsData = schedule.local(() -> {
            // Generate OKVS T_i ← Encode({x_{i,j}, v_{i,j} + F_K(x_{i,j})}_{j∈[m]})
            BigInteger[] data = okvs.encode(pnKeyValueMap(prfKey, inputPairs), true);
            // Masked OKVS T_i' = T_i + Γ_i, where Γ_i = G(s_i)
            addPrgVector(data, seed, false);
            return data;
        });

        sendBigIntegerArray(STEP, rpc.getParty(0), okvsData, pByteLength);

        endReduction();
        if (rpc.ownParty().getPartyId() == 2) {
            switch (resultType) {
                case AIDED -> runAidedServer();
            }
        }
    }

    /**
     * P1's protocol execution - Ring or tree topology
     */
    public BigInteger[] runP1Ring(KeyValuePair[] inputPairs) throws Exception {
        // Step 2: P1 samples and sends lambda seeds to P3-Pn
        byte[][] lambdaSeeds = new byte[parties - 2][secLevel / 8];
        for (int i = 0; i < lambdaSeeds.length; i++) {
            secureRandom.nextBytes(lambdaSeeds[i]);
        }

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), lambdaSeeds[k - 2]);
        }

        // T = T_n' + Λ_1 (ring) or T = sum_{c ∈ ch(1)} T_c' + Λ_1 (tree), where Λ_1 = -sum_{i=3}^{n} G(t_i)
        schedule.awaitTurn();
        BigInteger[] finalOkvsData = schedule.local(() -> {
            BigInteger[] data = new BigInteger[okvsSize];
            Arrays.fill(data, BigInteger.ZERO);
            for (byte[] seed : lambdaSeeds) {
                addPrgVector(data, seed, true);
            }
            return data;
        });
        addReceived(finalOkvsData, upstreamOf(0));

        BigInteger[] U = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            U[i] = okvs.decode(finalOkvsData, inputPairs[i].key());
        }
        return truncateP1(U, inputPairs);
    }

    /**
     * P2's protocol execution - Ring or tree topology
     */
    public void runP2Ring(KeyValuePair[] inputPairs) throws Exception {
        byte[] prfKey = new byte[secLevel / 8];
        secureRandom.nextBytes(prfKey);

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), prfKey);
        }

        byte[][] gammaSeeds = new byte[parties - 2][secLevel / 8];
        for (int i = 0; i < gammaSeeds.length; i++) {
            secureRandom.nextBytes(gammaSeeds[i]);
        }

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), gammaSeeds[k - 2]);
        }

        schedule.awaitTurn();
        BigInteger[] p2Random = new BigInteger[size];
        // T_2' = T_2 + Γ_2 with Γ_2 = -sum_{i=3}^{n} G(s_i), plus sum_{c ∈ ch(2)} T_c' in the tree
        BigInteger[] p2OkvsData = schedule.local(() -> {
            BigInteger[] data = okvs.encode(p2KeyValueMap(prfKey, inputPairs, p2Random), true);
            for (byte[] seed : gammaSeeds) {
                addPrgVector(data, seed, true);
            }
            return data;
        });
        addReceived(p2OkvsData, upstreamOf(1));

        sendBigIntegerArray(STEP,
                rpc.getParty(downstreamOf(1)), p2OkvsData, pByteLength);
        truncateP2(p2Random);
    }

    /**
     * P3-Pn parties' protocol execution - Ring or tree topology
     */
    public void runPnRing(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        byte[] prfKey = receiveByteArray(STEP, rpc.getParty(1));
        byte[] lambdaSeed = receiveByteArray(STEP, rpc.getParty(0));
        byte[] gammaSeed = receiveByteArray(STEP, rpc.getParty(1));

        // Compute T_i' = T_i + Λ_i + Γ_i + T_{i-1}' (ring) or + sum_{c ∈ ch(i)} T_c' (tree), where Λ_i = G(t_i) and
        // Γ_i = G(s_i)
        schedule.awaitTurn();
        BigInteger[] accumulatedOkvsData = schedule.local(() -> {
            BigInteger[] data = okvs.encode(pnKeyValueMap(prfKey, inputPairs), true);
            addPrgVector(data, lambdaSeed, false);
            addPrgVector(data, gammaSeed, false);
            return data;
        });
        addReceived(accumulatedOkvsData, upstreamOf(partyId));

        sendBigIntegerArray(STEP,
                rpc.getParty(downstreamOf(partyId)), accumulatedOkvsData, pByteLength);

        endReduction();
        if (rpc.ownParty().getPartyId() == 2) {
            switch (resultType) {
                case AIDED -> runAidedServer();
            }
        }
    }

    /**
     * P1's mod-q truncation, y_j = ⌊u_j / q⌋ and α_j = v_{1,j} + (u_j mod q), followed by the two-party protocol.
     */
    private BigInteger[] truncateP1(BigInteger[] U, KeyValuePair[] inputPairs) throws Exception {
        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            BigInteger[] quotientAndRemainder = U[i].divideAndRemainder(q);
            finalKeys[i] = quotientAndRemainder[0];
            BigInteger alpha = quotientAndRemainder[1].add(BigInteger.valueOf(inputPairs[i].value()));
            // LOOKUP needs α_j + β_j to be the weight sum itself, so α_j stays unreduced (below q + M)
            finalValues[i] = resultType == ResultType.LOOKUP ? alpha : alpha.mod(q);
        }

        endReduction();
        return switch (resultType) {
            case NONE -> null;
            case RAW -> {
                runRawP1(finalKeys, finalValues);
                yield null;
            }
            case AIDED -> runAidedP1(finalKeys, finalValues);
            case LOOKUP -> runLookupP1(finalKeys, finalValues);
        };
    }

    /**
     * P2's mod-q truncation, z_j = ⌊r_j / q⌋ and β_j = -(r_j mod q), followed by the two-party protocol. β_j is taken
     * mod q for AIDED and mod the prime of OffsetLookup for LOOKUP.
     */
    private void truncateP2(BigInteger[] p2Random) throws Exception {
        BigInteger lookupPrime = resultType == ResultType.LOOKUP ? OffsetLookup.prime(size, upperBoundM) : null;
        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];
        schedule.tail(() -> {
            for (int i = 0; i < size; i++) {
                BigInteger[] quotientAndRemainder = p2Random[i].divideAndRemainder(q);
                finalKeys[i] = quotientAndRemainder[0];
                finalValues[i] = resultType == ResultType.LOOKUP ? quotientAndRemainder[1].negate().mod(lookupPrime)
                        : zQ.neg(quotientAndRemainder[1]);
            }
        });

        endReduction();
        switch (resultType) {
            case RAW -> runRawP2(finalKeys, finalValues);
            case AIDED -> runAidedP2(finalKeys, finalValues);
            case LOOKUP -> runLookupP2(finalKeys, finalValues);
        }
    }

    public BigInteger[] runLookupP1(BigInteger[] keys, BigInteger[] values) throws Exception {
        OffsetLookup.P1 lookup = new OffsetLookup.P1(rpc, rpc.getParty(1), lookupConfig);
        lookup.init(size, upperBoundM);
        lookup.offline();
        offline = snapshot();
        return lookup.online(Arrays.stream(keys).map(BigInteger::toByteArray).toArray(byte[][]::new), values);
    }

    public void runLookupP2(BigInteger[] keys, BigInteger[] values) throws Exception {
        OffsetLookup.P2 lookup = new OffsetLookup.P2(rpc, rpc.getParty(0), lookupConfig);
        lookup.init(size, upperBoundM);
        lookup.offline();
        offline = snapshot();
        lookup.online(Arrays.stream(keys).map(BigInteger::toByteArray).toArray(byte[][]::new), values);
    }

    public void runRawP1(BigInteger[] keys, BigInteger[] values) {
        sendBigIntegerArray(STEP, rpc.getParty(1), keys, pByteLength);
        sendBigIntegerArray(STEP, rpc.getParty(1), values, qByteLength);

    }

    public void runRawP2(BigInteger[] keys, BigInteger[] values) {
        Map<BigInteger, BigInteger> p2Results = new HashMap<>();
        for (int i = 0; i < size; i++) {
            p2Results.put(keys[i], values[i]);
        }

        BigInteger[] receivedKeys = receiveBigIntegerArray(STEP, rpc.getParty(0));
        BigInteger[] receivedValues = receiveBigIntegerArray(STEP, rpc.getParty(0));

        int count = 0;
        for (int i = 0; i < size; i++) {
            if (p2Results.containsKey(receivedKeys[i])) {
                count += 1;
                if (config.isDebug()) {
                    System.out.println("Ring Match found: " + i + ", " + zQ.add(receivedValues[i], p2Results.get(receivedKeys[i])));
                }
            }
        }
        System.out.println("Found count: " + count);
    }

    public static final class HashCode {
        private final byte[] data;

        public HashCode(byte[] data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashCode that = (HashCode) o;
            return Arrays.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }

    public BigInteger[] runAidedP1(BigInteger[] keys, BigInteger[] values) {
        byte[] prfKey = receiveByteArray(STEP, rpc.getParty(1));
        List<byte[]> p1Keys = new ArrayList<>(keys.length);
        BigInteger[] p1Values = new BigInteger[keys.length];

        for (int i = 0; i < keys.length; i++) {
            byte[] hash = Arrays.copyOf(SHA256.digestToBytes(concat(prfKey, keys[i].toByteArray())), config.getPrfLength());
            p1Keys.add(hash);
            p1Values[i] = add(values[i], tildeF(prfKey, hash), q);
        }
        sendPayload(STEP, rpc.getParty(2), p1Keys);
        sendBigIntegerArray(STEP, rpc.getParty(2), p1Values, qByteLength);

        List<byte[]> serverKeys = receivePayload(STEP, rpc.getParty(2));
        BigInteger[] serverValues = receiveBigIntegerArray(STEP, rpc.getParty(2));
        Map<HashCode, BigInteger> serverMap = HashMap.newHashMap(keys.length);
        for (int i = 0; i < keys.length; i++) {
            serverMap.put(new HashCode(serverKeys.get(i)), serverValues[i]);
        }

        List<byte[]> p2Keys = receivePayload(STEP, rpc.getParty(1));
        BigInteger[] p2Values = receiveBigIntegerArray(STEP, rpc.getParty(1));

        BigInteger[] weightSums = new BigInteger[size];
        int count = 0;
        for (int i = 0; i < size; i++) {
            BigInteger serverValue = serverMap.get(new HashCode(p2Keys.get(i)));
            if (serverValue != null) {
                count += 1;
                weightSums[i] = add(p2Values[i], serverValue, q);
                if (config.isDebug()) {
                    System.out.println("Ring Match found: " + i + ", " + weightSums[i]);
                }
            }
        }
        System.out.println("Found count: " + count);
        return weightSums;
    }

    public void runAidedP2(BigInteger[] keys, BigInteger[] values) {
        byte[] prfKey = new byte[secLevel / 8];
        secureRandom.nextBytes(prfKey);
        sendByteArray(STEP, rpc.getParty(0), prfKey);
        byte[] serverPrfKey = new byte[secLevel / 8];
        secureRandom.nextBytes(serverPrfKey);
        sendByteArray(STEP, rpc.getParty(2), serverPrfKey);

        List<byte[]> p2Keys = new ArrayList<>(keys.length);
        BigInteger[] p2Values = new BigInteger[keys.length];

        for (int i = 0; i < keys.length; i++) {
            byte[] hash1 = Arrays.copyOf(SHA256.digestToBytes(concat(prfKey, keys[i].toByteArray())), config.getPrfLength());
            byte[] hash2 = Arrays.copyOf(SHA256.digestToBytes(concat(serverPrfKey, hash1)), config.getPrfLength());
            p2Keys.add(hash2);
            p2Values[i] = sub(sub(values[i], tildeF(prfKey, hash1), q), tildeF(serverPrfKey, hash1), q);
        }

        sendPayload(STEP, rpc.getParty(0), p2Keys);
        sendBigIntegerArray(STEP, rpc.getParty(0), p2Values, qByteLength);
    }

    public void runAidedServer() {
        byte[] serverPrfKey = receiveByteArray(STEP, rpc.getParty(1));

        List<byte[]> p1Keys = receivePayload(STEP, rpc.getParty(0));
        BigInteger[] p1Values = receiveBigIntegerArray(STEP, rpc.getParty(0));
        byte[][] serverKeys = new byte[p1Keys.size()][];
        BigInteger[] serverValues = new BigInteger[p1Keys.size()];

        // Entry i of S_1'' goes to position π(i)
        int[] pi = PermutationNetworkUtils.randomPermutation(p1Keys.size(), secureRandom);
        for (int i = 0; i < p1Keys.size(); i++) {
            byte[] hash = Arrays.copyOf(SHA256.digestToBytes(concat(serverPrfKey, p1Keys.get(i))), config.getPrfLength());
            serverKeys[pi[i]] = hash;
            serverValues[pi[i]] = add(p1Values[i], tildeF(serverPrfKey, p1Keys.get(i)), q);
        }

        sendPayload(STEP, rpc.getParty(0), Arrays.asList(serverKeys));
        sendBigIntegerArray(STEP, rpc.getParty(0), serverValues, qByteLength);
    }

    /**
     * F̃_k(h) ∈ Z_q of the server-aided protocol: SHA-256(k‖h‖1) mod q. The tags F̂_k(h) are SHA-256(k‖h), so a tag
     * reveals nothing about F̃_k(h). The 256-bit digest is within statistical distance 2^-λ of uniform mod q as long
     * as |q| + λ ≤ 256.
     */
    private BigInteger tildeF(byte[] key, byte[] h) {
        return new BigInteger(1, SHA256.digestToBytes(concat(concat(key, h), TILDE_DOMAIN))).mod(q);
    }

    /**
     * F_K(x) ∈ Z_p for the key of every pair: AES under K on the 8-byte key, hashed to Z_p.
     */
    private BigInteger[] prfValues(byte[] prfKey, KeyValuePair[] inputPairs) {
        byte[][] keys = Arrays.stream(inputPairs).map(pair -> LongUtils.longToByteArray(pair.key()))
                              .toArray(byte[][]::new);
        return zpHash.hashByValue(PRF_TWEAK, AesPrf.getBytes(prfKey, keys));
    }

    /**
     * P2's pairs x_{2,j} ↦ v_{2,j} + r_j - (n-2) * F_K(x_{2,j}), with r_j sampled into p2Random.
     */
    private Map<Long, BigInteger> p2KeyValueMap(byte[] prfKey, KeyValuePair[] inputPairs, BigInteger[] p2Random) {
        for (int i = 0; i < size; i++) {
            p2Random[i] = zP.createRandom(secureRandom);
        }
        BigInteger[] fk = prfValues(prfKey, inputPairs);
        BigInteger leaves = BigInteger.valueOf(parties - 2);
        Map<Long, BigInteger> keyValueMap = HashMap.newHashMap(size);
        for (int i = 0; i < size; i++) {
            keyValueMap.put(inputPairs[i].key(), add(BigInteger.valueOf(inputPairs[i].value()),
                    sub(p2Random[i], zP.mul(leaves, fk[i]), p), p));
        }
        return keyValueMap;
    }

    /**
     * The pairs x_{i,j} ↦ v_{i,j} + F_K(x_{i,j}) of P3-Pn.
     */
    private Map<Long, BigInteger> pnKeyValueMap(byte[] prfKey, KeyValuePair[] inputPairs) {
        BigInteger[] fk = prfValues(prfKey, inputPairs);
        Map<Long, BigInteger> keyValueMap = HashMap.newHashMap(size);
        for (int i = 0; i < size; i++) {
            keyValueMap.put(inputPairs[i].key(), add(BigInteger.valueOf(inputPairs[i].value()), fk[i], p));
        }
        return keyValueMap;
    }

    /**
     * Parties whose masked OKVS the given party adds before forwarding. Ring: P2 → P3 → … → Pn → P1. Tree: heap order
     * rooted at P1, so ch(i) = {2i, 2i+1} ∩ [n]. Party ids are 0-based, so P_i has id i-1.
     */
    private int[] upstreamOf(int partyId) {
        if (topologyType == TopologyType.TREE) {
            return IntStream.of(2 * partyId + 1, 2 * partyId + 2).filter(c -> c < parties).toArray();
        }
        if (partyId == 1) {
            return new int[0];
        }
        return new int[]{partyId == 0 ? parties - 1 : partyId - 1};
    }

    /**
     * Party that the given non-root party forwards its masked OKVS to: the next party (ring) or par(i) = ⌊i/2⌋ (tree).
     */
    private int downstreamOf(int partyId) {
        if (topologyType == TopologyType.TREE) {
            return (partyId - 1) / 2;
        }
        return (partyId + 1) % parties;
    }

    /**
     * Receives a masked OKVS from each source in turn and adds them into acc. The RPC layer buffers incoming packets
     * in the background, so transfers from different sources still overlap.
     */
    private void addReceived(BigInteger[] acc, int[] sources) {
        for (int k : sources) {
            List<byte[]> receivedOkvsData = receivePayload(STEP, rpc.getParty(k));
            MathPreconditions.checkEqual("receivedOkvsData.size()", "okvsSize", receivedOkvsData.size(), okvsSize);
            for (int i = 0; i < okvsSize; i++) {
                acc[i] = add(acc[i], BigIntegerUtils.byteArrayToNonNegBigInteger(receivedOkvsData.get(i)), p);
            }
        }
    }

    /**
     * Ends the reduction: its measurements, then the end of this party's turn.
     */
    private void endReduction() throws IOException {
        reduction = snapshot();
        okvs = null;
        schedule.endTurn();
    }

    private Phase snapshot() {
        long wallNanos = System.nanoTime() - startNanos;
        return new Phase(wallNanos, wallNanos - (meter.getWaitNanos() - waitNanosAtStart),
                rpc.getPayloadByteLength() - sentBytesAtStart, meter.getReceivedByteLength() - recvBytesAtStart);
    }

    /**
     * Adds the mask G(seed) ∈ Z_p^okvsSize into acc, or subtracts it. The PRG output is consumed element by element,
     * so G(seed) is never held in full.
     */
    private void addPrgVector(BigInteger[] acc, byte[] seed, boolean subtract) {
        SecureRandom prg = CommonUtils.createSeedSecureRandom();
        prg.setSeed(seed);
        for (int i = 0; i < okvsSize; i++) {
            BigInteger mask = zP.createRandom(prg);
            acc[i] = subtract ? sub(acc[i], mask, p) : add(acc[i], mask, p);
        }
    }

    /**
     * Helper method to send an array of non-negative BigIntegers, each encoded in byteLength bytes
     */
    private void sendBigIntegerArray(int stepId, Party targetParty, BigInteger[] data, int byteLength) {
        List<byte[]> payload = Arrays.stream(data)
                                     .map(x -> BigIntegerUtils.nonNegBigIntegerToByteArray(x, byteLength))
                                     .collect(Collectors.toList());
        sendPayload(stepId, targetParty, payload);
    }

    /**
     * Helper method to receive an array of non-negative BigIntegers
     */
    private BigInteger[] receiveBigIntegerArray(int stepId, Party sourceParty) {
        List<byte[]> payload = receivePayload(stepId, sourceParty);
        return payload.stream()
                      .map(BigIntegerUtils::byteArrayToNonNegBigInteger)
                      .toArray(BigInteger[]::new);
    }

    /**
     * Helper method to send byte array
     */
    private void sendByteArray(int stepId, Party targetParty, byte[] data) {
        List<byte[]> payload = List.of(data);
        sendPayload(stepId, targetParty, payload);
    }

    /**
     * Helper method to receive byte array
     */
    private byte[] receiveByteArray(int stepId, Party sourceParty) {
        List<byte[]> payload = receivePayload(stepId, sourceParty);
        return payload.getFirst();
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Protocol description
     */
    public static class PcwsPtoDesc implements PtoDesc {
        private static final int PTO_ID = 0x20250625; // Replace with actual serialVersionUID
        private static final String PTO_NAME = "PCWS Protocol";
        private static final PcwsPtoDesc INSTANCE = new PcwsPtoDesc();

        private PcwsPtoDesc() {
            // Private constructor
        }

        public static PtoDesc getInstance() {
            return INSTANCE;
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

    /**
     * Protocol configuration
     */
    public static class Config extends AbstractMultiPartyPtoConfig {
        private final int secLevel;
        private final int statLevel;
        private final int parties;
        private final int size;
        private final int threshold;
        private final BigInteger upperBoundM;
        private final BigInteger p;
        private final BigInteger q;
        private final ZpDokvsType zpDokvsType;
        private final TopologyType topologyType;
        private final ResultType resultType;
        private final boolean debug;
        private final boolean silent;
        private final int prfLength = 16; // > 40 + 2log(input)

        private Config(Builder builder) {
            super(SecurityModel.SEMI_HONEST);
            this.secLevel = builder.secLevel;
            this.statLevel = builder.statLevel;
            this.parties = builder.parties;
            this.size = builder.size;
            this.threshold = builder.threshold;
            this.upperBoundM = builder.upperBoundM;
            this.p = builder.p;
            this.q = builder.q;
            this.zpDokvsType = builder.zpDokvsType;
            this.topologyType = builder.topologyType;
            this.resultType = builder.resultType;
            this.debug = builder.debug;
            this.silent = builder.silent;
        }

        public int getSecLevel() {
            return secLevel;
        }

        public int getStatLevel() {
            return statLevel;
        }

        public int getParties() {
            return parties;
        }

        public int getSize() {
            return size;
        }

        public int getThreshold() {
            return threshold;
        }

        public BigInteger getUpperBoundM() {
            return upperBoundM;
        }

        public BigInteger getP() {
            return p;
        }

        public BigInteger getQ() {
            return q;
        }

        public ZpDokvsType getZpDokvsType() {
            return zpDokvsType;
        }

        public TopologyType getTopologyType() {
            return topologyType;
        }

        public ResultType getResultType() {
            return resultType;
        }

        public boolean isDebug() {
            return debug;
        }

        public int getPrfLength() {
            return prfLength;
        }

        /**
         * Whether LOOKUP's permute-and-share uses silent OT extension instead of IKNP.
         */
        public boolean isSilent() {
            return silent;
        }

        public static class Builder {
            private int secLevel = 128;
            private int statLevel = 40;
            private int parties = 3;
            private int size = 1000;
            private int threshold = 2;
            private BigInteger upperBoundM = BigInteger.valueOf(1000000);
            private BigInteger p;
            private BigInteger q;
            private ZpDokvsType zpDokvsType = ZpDokvsType.H3_SPARSE_CLUSTER_BLAZE_GCT;
            private TopologyType topologyType = TopologyType.STAR;
            private ResultType resultType = ResultType.NONE;
            private boolean debug = false;
            private boolean silent = false;

            public Builder setSecLevel(int secLevel) {
                this.secLevel = secLevel;
                return this;
            }

            public Builder setStatLevel(int statLevel) {
                this.statLevel = statLevel;
                return this;
            }

            public Builder setParties(int parties) {
                this.parties = parties;
                return this;
            }

            public Builder setSize(int size) {
                this.size = size;
                return this;
            }

            public Builder setThreshold(int threshold) {
                this.threshold = threshold;
                return this;
            }

            public Builder setUpperBoundM(BigInteger M) {
                this.upperBoundM = M;
                return this;
            }

            public Builder setP(BigInteger p) {
                this.p = p;
                return this;
            }

            public Builder setQ(BigInteger q) {
                this.q = q;
                return this;
            }

            public Builder setZpDokvsType(ZpDokvsType zpDokvsType) {
                this.zpDokvsType = zpDokvsType;
                return this;
            }

            public Builder setTopologyType(TopologyType topologyType) {
                this.topologyType = topologyType;
                return this;
            }

            public Builder setResultType(ResultType resultType) {
                this.resultType = resultType;
                return this;
            }

            public Builder setDebug(boolean debug) {
                this.debug = debug;
                return this;
            }

            public Builder setSilent(boolean silent) {
                this.silent = silent;
                return this;
            }

            public Config build() {
                if (this.q == null) {
                    // smallest prime above M·2^λ
                    BigInteger minQ = BigInteger.valueOf(2).pow(statLevel)
                                                .multiply(upperBoundM);
                    this.q = minQ.nextProbablePrime();
                    System.out.println("q not set, generated " + this.q.bitLength() + "-bit " + this.q);
                }
                if (this.p == null) {
                    // smallest prime above q·m²·2^λ
                    BigInteger minP = BigInteger.valueOf(2).pow(statLevel)
                                                .multiply(q)
                                                .multiply(BigInteger.valueOf(size).pow(2));
                    this.p = minP.nextProbablePrime();
                    System.out.println("p not set, generated " + this.p.bitLength() + "-bit " + this.p);
                }
                return new Config(this);
            }
        }
    }

    /**
     * Topology type enum. AIDED and LOOKUP skip the reduction and run that two-party protocol on the raw inputs of P1
     * and P2.
     */
    public enum TopologyType {
        STAR, RING, TREE, AIDED, LOOKUP
    }

    /**
     * Two-party protocol that follows the reduction: none, P1 sending its pairs to P2 in the clear, server-aided with
     * P3 as the server, or offset lookup.
     */
    public enum ResultType {
        NONE, RAW, AIDED, LOOKUP
    }

    /**
     * Key-Value pair class
     */
    public record KeyValuePair(long key, long value) {
    }

    /**
     * Measurements since execute() started: wall time, compute time (wall time minus time blocked in receive), and
     * payload bytes sent and received.
     */
    public record Phase(long wallNanos, long computeNanos, long sentBytes, long recvBytes) {
    }
}