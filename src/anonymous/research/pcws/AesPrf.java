package anonymous.research.pcws;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory.PrfType;

/**
 * mpc4j's JDK_AES_CBC PRF evaluated on a batch of messages. On a message x of at most one block it is AES_k(x‖0…0),
 * so all of those take one ECB call; a longer message goes through mpc4j's PRF. An output shorter than a block is a
 * prefix of the block.
 */
final class AesPrf {
    private static final int BLOCK = CommonConstants.BLOCK_BYTE_LENGTH;

    private AesPrf() {
        // empty
    }

    /**
     * The 16-byte outputs of the PRF under the key, block i for message i.
     */
    static byte[] getBytes(byte[] key, byte[][] messages) {
        byte[] input = new byte[messages.length * BLOCK];
        for (int i = 0; i < messages.length; i++) {
            if (messages[i].length <= BLOCK) {
                System.arraycopy(messages[i], 0, input, i * BLOCK, messages[i].length);
            }
        }
        byte[] output;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            output = cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        Prf prf = null;
        for (int i = 0; i < messages.length; i++) {
            if (messages[i].length > BLOCK) {
                if (prf == null) {
                    prf = PrfFactory.createInstance(PrfType.JDK_AES_CBC, BLOCK);
                    prf.setKey(key);
                }
                System.arraycopy(prf.getBytes(messages[i]), 0, output, i * BLOCK, BLOCK);
            }
        }
        return output;
    }

    /**
     * Prf.getInteger(x, bound) of the PRF with 4-byte outputs, for every message x.
     */
    static int[] getIntegers(byte[] key, byte[][] messages, int bound) {
        ByteBuffer output = ByteBuffer.wrap(getBytes(key, messages));
        int[] integers = new int[messages.length];
        for (int i = 0; i < messages.length; i++) {
            integers[i] = Math.abs(output.getInt(i * BLOCK) % bound);
        }
        return integers;
    }
}
