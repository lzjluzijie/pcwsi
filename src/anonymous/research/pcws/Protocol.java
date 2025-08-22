package anonymous.research.pcws;

import static edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory.HashType.JDK_SHA256;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPto;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.SparseZpDokvs;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.ZpDokvsFactory;
import edu.alibaba.mpc4j.common.structure.okve.dokvs.zp.ZpDokvsFactory.ZpDokvsType;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.Zp;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpFactory;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

/**
 * PCWS (Private Computation Weighted Sum) Protocol Implementation
 * <p>
 * This protocol implements a multi-party computation for computing weighted sums
 * over key-value pairs with privacy preservation.
 *
 * @author Zijie Lu
 */
public class Protocol extends AbstractMultiPartyPto {
    private static final Hash SHA256 = HashFactory.createInstance(JDK_SHA256, 32);
    private static final int STEP = 0;

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
    private final SecureRandom secureRandom;
    private final Prf prf;             // PRF for F: {0,1}^κ × {0,1}^l → Z_p
    private final SparseZpDokvs<Long> okvs;  // OKVS instance

    /**
     * Constructor
     */
    public Protocol(Rpc rpc, Config config, Party... otherParties) {
        super(PcwsPtoDesc.getInstance(), config, rpc, otherParties);

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

        this.secureRandom = new SecureRandom();
        this.prf = PrfFactory.createInstance(envType, secLevel / 8);

        // Initialize OKVS with H3_SPARSE_CLUSTER_BLAZE_GCT
        byte[][] okvsKeys = new byte[3][secLevel / 8]; // H3 requires 3 keys
        for (int i = 0; i < 3; i++) {
            okvsKeys[i][i] = (byte) i;
        }
        this.okvs = ZpDokvsFactory.createSparseInstance(
                envType, zpDokvsType, p, size, okvsKeys
        );
    }

    public Config getConfig() {
        return config;
    }

    /**
     * Main protocol execution
     */
    public void execute(KeyValuePair[] inputPairs) throws Exception {
        switch (topologyType) {
            case RING -> executeRing(inputPairs);
            case STAR -> executeStar(inputPairs);
        }
    }

    /**
     * Star topology execution
     */
    public void executeStar(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        if (partyId == 0) {
            runP1Star(inputPairs);
        } else if (partyId == 1) {
            runP2Star(inputPairs);
        } else {
            runPnStar(inputPairs);
        }
    }

    /**
     * Ring topology execution
     */
    public void executeRing(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        if (partyId == 0) {
            runP1Ring(inputPairs);
        } else if (partyId == 1) {
            runP2Ring(inputPairs);
        } else {
            runPnRing(inputPairs);
        }
    }

    /**
     * P1's protocol execution - Star topology
     */
    public void runP1Star(KeyValuePair[] inputPairs) throws Exception {
        // P1 computes T = sum_{i=2}^{n} T_i' and U = {u_j | u_j = Decode(T, x_{1,j}), j ∈ [m]}
        BigInteger[] okvsData = new BigInteger[okvsSize];
        Arrays.fill(okvsData, BigInteger.ZERO);

        // Receive masked OKVS from P2
        BigInteger[] p2OkvsData = receiveBigIntegerArray(STEP, rpc.getParty(1));
        for (int i = 0; i < okvsSize; i++) {
            okvsData[i] = zP.add(okvsData[i], p2OkvsData[i]);
        }

        // Receive masked OKVS from P3-Pn asynchronously
        List<CompletableFuture<BigInteger[]>> recvOkvsFutures =
                IntStream.range(2, parties)
                         .mapToObj(k -> CompletableFuture.supplyAsync(() ->
                                 receiveBigIntegerArray(STEP, rpc.getParty(k))
                         )).toList();
        List<BigInteger[]> receivedOkvsList = recvOkvsFutures.stream().map(CompletableFuture::join).toList();
        for (BigInteger[] receivedOkvsData : receivedOkvsList) {
            for (int i = 0; i < okvsSize; i++) {
                okvsData[i] = zP.add(okvsData[i], receivedOkvsData[i]);
            }
        }

        // Decode U = {u_j | u_j = Decode(T, x_{1,j}), j ∈ [m]}
        BigInteger[] U = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            U[i] = okvs.decode(okvsData, inputPairs[i].key());
        }

        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];

        for (int i = 0; i < size; i++) {
            // Compute y_j = floor(u_j / q) ∈ Z_q
            finalKeys[i] = U[i].divide(q);
            finalValues[i] = zQ.add(U[i].mod(q), BigInteger.valueOf(inputPairs[i].value()));
        }

        switch (resultType) {
            case RAW -> runRawP1(finalKeys, finalValues);
            case AIDED -> runAidedP1(finalKeys, finalValues);
        }
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

        BigInteger[] maskData = new BigInteger[okvsSize];
        Arrays.fill(maskData, BigInteger.ZERO);
        for (int k = 2; k < parties; k++) {
            BigInteger[] otherMaskData = generatePRGVector(seeds[k - 2]);
            for (int i = 0; i < okvsSize; i++) {
                maskData[i] = zP.sub(maskData[i], otherMaskData[i]);
            }
        }

        BigInteger[] p2Random = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            p2Random[i] = zP.createRandom(secureRandom);
        }

        prf.setKey(prfKey);

        Map<Long, BigInteger> keyValueMap = new HashMap<>();
        for (int i = 0; i < size; i++) {
            long key = inputPairs[i].key();
            long value = inputPairs[i].value();

            // Compute F_K(x_{2,j})
            BigInteger fkValue = zP.createRandom(prf.getBytes(BigInteger.valueOf(key).toByteArray()));

            // Compute v_{2,j} + r_j - (n-2) * F_K(x_{2,j})
            BigInteger valueResult = zP.add(BigInteger.valueOf(value), zP.sub(p2Random[i], zP.mul(BigInteger.valueOf(parties - 2), fkValue)));

            keyValueMap.put(key, valueResult);
        }

        BigInteger[] okvsData = okvs.encode(keyValueMap, false);

        // Send masked OKVS T_2' = T_2 + Γ_2 to P1
        for (int i = 0; i < okvsSize; i++) {
            okvsData[i] = zP.add(okvsData[i], maskData[i]);
        }

        sendBigIntegerArray(STEP, rpc.getParty(0), okvsData);

        // P2 performs modulo-q truncation for r_j values
        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            finalKeys[i] = p2Random[i].divide(q);
            finalValues[i] = zQ.neg(p2Random[i]);
        }

        switch (resultType) {
            case RAW -> runRawP2(finalKeys, finalValues);
            case AIDED -> runAidedP2(finalKeys, finalValues);
        }
    }

    /**
     * P3-Pn parties' protocol execution - Star topology
     */
    public void runPnStar(KeyValuePair[] inputPairs) throws Exception {
        byte[] prfKey = receiveByteArray(STEP,
                rpc.getParty(1));

        byte[] seed = receiveByteArray(STEP,
                rpc.getParty(1));
        SecureRandom seededRandom = new SecureRandom(seed);

        BigInteger[] maskData = generatePRGVector(seed);

        prf.setKey(prfKey);

        // Generate OKVS T_i ← Encode({x_{i,j}, v_{i,j} + F_K(x_{i,j})}_{j∈[m]})
        Map<Long, BigInteger> keyValueMap = new HashMap<>();
        for (int i = 0; i < size; i++) {
            long key = inputPairs[i].key();
            long value = inputPairs[i].value();

            // Compute F_K(x_{i,j})
            BigInteger fkValue = zP.createRandom(prf.getBytes(BigInteger.valueOf(key).toByteArray()));
//            BigInteger fkValue = zP.createZero();

            // Compute v_{i,j} + F_K(x_{i,j})
            BigInteger valueResult = zP.add(BigInteger.valueOf(value), fkValue);

            keyValueMap.put(key, valueResult);
        }

        BigInteger[] okvsData = okvs.encode(keyValueMap, false);

        // Send masked OKVS T_i' = T_i + Γ_i to P1
        BigInteger[] okvsMaskedData = new BigInteger[okvsSize];
        for (int i = 0; i < okvsSize; i++) {
            okvsMaskedData[i] = okvsData[i].add(maskData[i]).mod(p);
        }

        sendBigIntegerArray(STEP, rpc.getParty(0), okvsMaskedData);

        if (rpc.ownParty().getPartyId() == 2) {
            switch (resultType) {
                case AIDED -> runAidedServer();
            }
        }
    }

    /**
     * P1's protocol execution - Ring topology
     */
    public void runP1Ring(KeyValuePair[] inputPairs) throws Exception {
        // Step 2: P1 samples and sends lambda seeds to P3-Pn
        byte[][] lambdaSeeds = new byte[parties - 2][secLevel / 8];
        for (int i = 0; i < lambdaSeeds.length; i++) {
            secureRandom.nextBytes(lambdaSeeds[i]);
        }

        for (int k = 2; k < parties; k++) {
            sendByteArray(STEP,
                    rpc.getParty(k), lambdaSeeds[k - 2]);
        }

        BigInteger[] maskData = new BigInteger[okvsSize];
        Arrays.fill(maskData, BigInteger.ZERO);
        for (int k = 2; k < parties; k++) {
            BigInteger[] otherMaskData = generatePRGVector(lambdaSeeds[k - 2]);
            for (int i = 0; i < okvsSize; i++) {
                maskData[i] = zP.sub(maskData[i], otherMaskData[i]);
            }
        }

        BigInteger[] finalOkvsData = receiveBigIntegerArray(
                STEP,
                rpc.getParty(parties - 1));

        for (int i = 0; i < okvsSize; i++) {
            finalOkvsData[i] = zP.add(finalOkvsData[i], maskData[i]);
        }

        BigInteger[] U = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            U[i] = okvs.decode(finalOkvsData, inputPairs[i].key());
        }

        // Modulo-q truncation and send to P2
        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];

        for (int i = 0; i < size; i++) {
            finalKeys[i] = U[i].divide(q);
            finalValues[i] = zQ.add(U[i].mod(q), BigInteger.valueOf(inputPairs[i].value()));
        }

        switch (resultType) {
            case RAW -> runRawP1(finalKeys, finalValues);
            case AIDED -> runAidedP1(finalKeys, finalValues);
        }
    }

    /**
     * P2's protocol execution - Ring topology
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

        BigInteger[] maskData = new BigInteger[okvsSize];
        Arrays.fill(maskData, BigInteger.ZERO);
        for (int k = 2; k < parties; k++) {
            BigInteger[] otherMaskData = generatePRGVector(gammaSeeds[k - 2]);
            for (int i = 0; i < okvsSize; i++) {
                maskData[i] = zP.sub(maskData[i], otherMaskData[i]);
            }
        }

        BigInteger[] p2Random = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            p2Random[i] = zP.createRandom(secureRandom);
        }

        prf.setKey(prfKey);
        Map<Long, BigInteger> keyValueMap = new HashMap<>();
        for (int i = 0; i < size; i++) {
            long key = inputPairs[i].key();
            long value = inputPairs[i].value();

            BigInteger fkValue = zP.createRandom(prf.getBytes(BigInteger.valueOf(key).toByteArray()));
            BigInteger valueResult = zP.add(BigInteger.valueOf(value),
                    zP.sub(p2Random[i], zP.mul(BigInteger.valueOf(parties - 2), fkValue)));

            keyValueMap.put(key, valueResult);
        }

        BigInteger[] p2OkvsData = okvs.encode(keyValueMap, false);
        for (int i = 0; i < okvsSize; i++) {
            p2OkvsData[i] = zP.add(p2OkvsData[i], maskData[i]);
        }

        sendBigIntegerArray(STEP,
                rpc.getParty(2), p2OkvsData);

        // P2 performs modulo-q truncation for r_j values and check matches
        BigInteger[] finalKeys = new BigInteger[size];
        BigInteger[] finalValues = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            finalKeys[i] = p2Random[i].divide(q);
            finalValues[i] = zQ.neg(p2Random[i]);
        }

        switch (resultType) {
            case RAW -> runRawP2(finalKeys, finalValues);
            case AIDED -> runAidedP2(finalKeys, finalValues);
        }
    }

    /**
     * P3-Pn parties' protocol execution - Ring topology
     */
    public void runPnRing(KeyValuePair[] inputPairs) throws Exception {
        int partyId = rpc.ownParty().getPartyId();

        byte[] prfKey = receiveByteArray(STEP, rpc.getParty(1));
        byte[] lambdaSeed = receiveByteArray(STEP, rpc.getParty(0));
        byte[] gammaSeed = receiveByteArray(STEP, rpc.getParty(1));

        BigInteger[] lambdaVector = generatePRGVector(lambdaSeed);
        BigInteger[] gammaVector = generatePRGVector(gammaSeed);

        prf.setKey(prfKey);
        Map<Long, BigInteger> keyValueMap = new HashMap<>();
        for (int i = 0; i < size; i++) {
            long key = inputPairs[i].key();
            long value = inputPairs[i].value();

            BigInteger fkValue = zP.createRandom(prf.getBytes(BigInteger.valueOf(key).toByteArray()));
            BigInteger valueResult = zP.add(BigInteger.valueOf(value), fkValue);

            keyValueMap.put(key, valueResult);
        }

        BigInteger[] ownOkvsData = okvs.encode(keyValueMap, false);

        BigInteger[] prevOkvsData;
        if (partyId == 2) {
            // P3 receives from P2
            prevOkvsData = receiveBigIntegerArray(STEP, rpc.getParty(1));
        } else {
            // Pi receives from Pi-1
            prevOkvsData = receiveBigIntegerArray(STEP, rpc.getParty(partyId - 1));
        }

        // Compute T_i' = T_i + T_{i-1}' + Λ_i + Γ_i
        BigInteger[] accumulatedOkvsData = new BigInteger[okvsSize];
        for (int i = 0; i < okvsSize; i++) {
            accumulatedOkvsData[i] = zP.add(ownOkvsData[i], prevOkvsData[i]);
            accumulatedOkvsData[i] = zP.add(accumulatedOkvsData[i], lambdaVector[i]);
            accumulatedOkvsData[i] = zP.add(accumulatedOkvsData[i], gammaVector[i]);
        }

        // Send to next party
        if (partyId == parties - 1) {
            // Pn sends to P1
            sendBigIntegerArray(STEP,
                    rpc.getParty(0), accumulatedOkvsData);
        } else {
            // Pi sends to Pi+1
            sendBigIntegerArray(STEP,
                    rpc.getParty(partyId + 1), accumulatedOkvsData);
        }

        if (rpc.ownParty().getPartyId() == 2) {
            switch (resultType) {
                case AIDED -> runAidedServer();
            }
        }
    }

    public void runRawP1(BigInteger[] keys, BigInteger[] values) {
        sendBigIntegerArray(STEP, rpc.getParty(1), keys);
        sendBigIntegerArray(STEP, rpc.getParty(1), values);

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

    public void runAidedP1(BigInteger[] keys, BigInteger[] values) {
        byte[] prfKey = receiveByteArray(STEP, rpc.getParty(1));
        List<byte[]> p1Keys = new ArrayList<>(keys.length);
        BigInteger[] p1Values = new BigInteger[keys.length];

        for (int i = 0; i < keys.length; i++) {
            byte[] hash = Arrays.copyOf(SHA256.digestToBytes(concat(prfKey, keys[i].toByteArray())), config.getPrfLength());
            p1Keys.add(hash);
            p1Values[i] = zQ.add(values[i], zQ.createRandom(concat(prfKey, hash)));
        }
        sendPayload(STEP, rpc.getParty(2), p1Keys);
        sendBigIntegerArray(STEP, rpc.getParty(2), p1Values);

        List<byte[]> serverKeys = receivePayload(STEP, rpc.getParty(2));
        BigInteger[] serverValues = receiveBigIntegerArray(STEP, rpc.getParty(2));
        HashMap<HashCode, BigInteger> serverMap = new HashMap<>(keys.length);
        for (int i = 0; i < keys.length; i++) {
            serverMap.put(new HashCode(serverKeys.get(i)), serverValues[i]);
        }

        List<byte[]> p2Keys = receivePayload(STEP, rpc.getParty(1));
        BigInteger[] p2Values = receiveBigIntegerArray(STEP, rpc.getParty(1));

        int count = 0;
        for (int i = 0; i < size; i++) {
            HashCode hashCode = new HashCode(p2Keys.get(i));
            if (serverMap.containsKey(hashCode)) {
                count += 1;
                if (config.isDebug()) {
                    System.out.println("Ring Match found: " + i + ", " + zQ.add(p2Values[i], serverMap.get(hashCode)));
                }
            }
        }
        System.out.println("Found count: " + count);
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
            p2Values[i] = zQ.sub(zQ.sub(values[i], zQ.createRandom(concat(prfKey, hash1))),
                    zQ.createRandom(concat(serverPrfKey, hash1)));
        }

        sendPayload(STEP, rpc.getParty(0), p2Keys);
        sendBigIntegerArray(STEP, rpc.getParty(0), p2Values);
    }

    public void runAidedServer() {
        byte[] serverPrfKey = receiveByteArray(STEP, rpc.getParty(1));

        List<byte[]> p1Keys = receivePayload(STEP, rpc.getParty(0));
        BigInteger[] p1Values = receiveBigIntegerArray(STEP, rpc.getParty(0));
        List<byte[]> serverKeys = new ArrayList<>(p1Keys.size());
        BigInteger[] serverValues = new BigInteger[p1Keys.size()];

        for (int i = 0; i < p1Keys.size(); i++) {
            byte[] hash = Arrays.copyOf(SHA256.digestToBytes(concat(serverPrfKey, p1Keys.get(i))), config.getPrfLength());
            serverKeys.add(hash);
            serverValues[i] = zQ.add(p1Values[i], zQ.createRandom(concat(serverPrfKey, p1Keys.get(i))));
        }

        // permute

        sendPayload(STEP, rpc.getParty(0), serverKeys);
        sendBigIntegerArray(STEP, rpc.getParty(0), serverValues);
    }

    /**
     * Generate PRG vector from seed
     */
    private BigInteger[] generatePRGVector(byte[] seed) {
//        System.out.println(this.ownParty().getPartyId());
//        System.out.println(Arrays.toString(seed));

        SecureRandom prg = CommonUtils.createSeedSecureRandom();
        prg.setSeed(seed);
        BigInteger[] vector = new BigInteger[okvsSize];
        for (int i = 0; i < okvsSize; i++) {
            vector[i] = zP.createRandom(prg);
        }
        return vector;
    }

    /**
     * Helper method to send BigInteger array
     */
    private void sendBigIntegerArray(int stepId, Party targetParty, BigInteger[] data) {
        List<byte[]> payload = Arrays.stream(data)
                                     .map(BigIntegerUtils::bigIntegerToByteArray)
                                     .collect(Collectors.toList());
        sendPayload(stepId, targetParty, payload);
    }

    /**
     * Helper method to receive BigInteger array
     */
    private BigInteger[] receiveBigIntegerArray(int stepId, Party sourceParty) {
        List<byte[]> payload = receivePayload(stepId, sourceParty);
        return payload.stream()
                      .map(BigInteger::new)
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

            public Config build() {
//                Random random = new SecureRandom();
                Random random = new Random(2025);
                if (this.q == null) {
                    BigInteger minQ = BigInteger.valueOf(2).pow(statLevel)
                                                .multiply(upperBoundM);
                    int minLogQ = minQ.bitLength();
                    this.q = BigInteger.probablePrime(minLogQ, random);
                    System.out.println("q not set, minimal length " + minLogQ + ", generated " + this.q);
                }
                if (this.p == null) {
                    BigInteger minP = BigInteger.valueOf(2).pow(statLevel)
                                                .multiply(q)
                                                .multiply(BigInteger.valueOf(size).pow(2));
                    int minLogP = minP.bitLength();
                    this.p = BigInteger.probablePrime(minLogP, random);
                    System.out.println("p not set, minimal length " + minLogP + ", generated " + this.p);
                }
                return new Config(this);
            }
        }
    }

    /**
     * Topology type enum
     */
    public enum TopologyType {
        STAR, RING, AIDED
    }

    public enum ResultType {
        NONE, RAW, AIDED
    }

    /**
     * Key-Value pair class
     */
    public record KeyValuePair(long key, long value) {
    }
}