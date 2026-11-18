package anonymous.research.pcws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.IntStream;

import org.junit.Test;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.utils.BlockUtils;

/**
 * Checks AesPrf against mpc4j's PRF of the STANDARD environment, on messages shorter than, as long as and longer
 * than a block.
 */
public class AesPrfTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BLOCK = CommonConstants.BLOCK_BYTE_LENGTH;

    @Test
    public void testGetBytes() {
        byte[] key = BlockUtils.randomBlock(RANDOM);
        Prf prf = PrfFactory.createInstance(EnvType.STANDARD, BLOCK);
        prf.setKey(key);
        byte[][] messages = messages();
        byte[] output = AesPrf.getBytes(key, messages);
        for (int i = 0; i < messages.length; i++) {
            assertArrayEquals(prf.getBytes(messages[i]), Arrays.copyOfRange(output, i * BLOCK, (i + 1) * BLOCK));
        }
    }

    @Test
    public void testGetIntegers() {
        byte[] key = BlockUtils.randomBlock(RANDOM);
        Prf prf = PrfFactory.createInstance(EnvType.STANDARD, Integer.BYTES);
        prf.setKey(key);
        byte[][] messages = messages();
        for (int bound : new int[]{1, 2, 3, 1000, OffsetLookup.binNum(1 << 20), Integer.MAX_VALUE}) {
            int[] integers = AesPrf.getIntegers(key, messages, bound);
            for (int i = 0; i < messages.length; i++) {
                assertEquals(prf.getInteger(messages[i], bound), integers[i]);
            }
        }
    }

    /**
     * Five random messages of each length from 1 to 40 bytes.
     */
    private static byte[][] messages() {
        return IntStream.range(0, 200).mapToObj(i -> {
            byte[] message = new byte[1 + i / 5];
            RANDOM.nextBytes(message);
            return message;
        }).toArray(byte[][]::new);
    }
}
