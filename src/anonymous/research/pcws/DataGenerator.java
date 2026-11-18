package anonymous.research.pcws;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import java.util.stream.Collectors;

/**
 * Synthetic PC-WSI inputs. Each party derives its set from a shared seed, so separate processes agree on the common
 * items without communicating.
 */
public final class DataGenerator {
    private DataGenerator() {
    }

    /**
     * Generates the input of one party (0-based ID).
     * <p>
     * Items 0, ..., ⌊ratio·m⌋-1 are held by every party; the remaining items of P_i are unique to P_i. Weights are
     * uniform in [0, ⌊M/n⌋), so every weight sum stays below M. Each party's list is shuffled independently.
     */
    public static Protocol.KeyValuePair[] generate(long seed, int parties, int size, double ratio,
                                                   BigInteger upperBoundM, int partyId) {
        int common = (int) (ratio * size);
        long maxWeight = upperBoundM.longValueExact() / parties;
        SplittableRandom random = new SplittableRandom(seed + 0x9E3779B97F4A7C15L * partyId);
        Protocol.KeyValuePair[] pairs = new Protocol.KeyValuePair[size];
        for (int j = 0; j < size; j++) {
            long key = j < common ? j : ((long) (partyId + 1) << 32) | j;
            pairs[j] = new Protocol.KeyValuePair(key, random.nextLong(maxWeight));
        }
        Collections.shuffle(Arrays.asList(pairs), random);
        return pairs;
    }

    /**
     * Ideal PC-WSI output of P1: for each item of P2, in P2's order, the weight sum over the given inputs if every one
     * of them holds the item, otherwise null. inputs[1] is P2's input.
     */
    public static BigInteger[] idealWeightSums(Protocol.KeyValuePair[][] inputs) {
        List<Map<Long, Long>> weights = Arrays.stream(inputs)
                .map(pairs -> Arrays.stream(pairs).collect(
                        Collectors.toMap(Protocol.KeyValuePair::key, Protocol.KeyValuePair::value)))
                .toList();
        return Arrays.stream(inputs[1]).map(pair -> {
            long sum = 0;
            for (Map<Long, Long> partyWeights : weights) {
                Long weight = partyWeights.get(pair.key());
                if (weight == null) {
                    return null;
                }
                sum += weight;
            }
            return BigInteger.valueOf(sum);
        }).toArray(BigInteger[]::new);
    }
}
