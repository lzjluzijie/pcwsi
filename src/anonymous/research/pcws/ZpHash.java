package anonymous.research.pcws;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.utils.BlockUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

/**
 * Hashes 16-byte blocks to Z_p. Output block j of the block x is mpc4j's TMMO with tweak t = (tweak, index) under
 * fixed-key AES π, i.e. π(π(x) ⊕ t) ⊕ π(x). Each pass of π is one ECB call over the batch, and π(x) is shared by all
 * j. The blocks give an L-bit y with L ≥ |p| + 40, mapped to ⌊y·p / 2^L⌋. Like y mod p, every value has ⌊2^L / p⌋ or
 * ⌈2^L / p⌉ preimages, so the result is within statistical distance 2^-40 of uniform, but it needs no division. L is a
 * multiple of 32, so the shift moves whole words.
 */
final class ZpHash {
    private static final int BLOCK = CommonConstants.BLOCK_BYTE_LENGTH;
    private final BigInteger p;
    private final int byteLength;
    private final int blocks;
    private final Cipher pi;

    ZpHash(BigInteger p) {
        this.p = p;
        byteLength = Integer.BYTES * CommonUtils.getUnitNum(p.bitLength() + CommonConstants.STATS_BIT_LENGTH,
                Integer.SIZE);
        blocks = CommonUtils.getUnitNum(byteLength, BLOCK);
        try {
            pi = Cipher.getInstance("AES/ECB/NoPadding");
            pi.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(BlockUtils.zeroBlock(), "AES"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Hashes block s of the batch with index s · blocks + j, as mpc4j's TMMO does for a batch.
     */
    BigInteger[] hash(int tweak, byte[][] xs) {
        return hash(tweak, concat(xs), blocks);
    }

    /**
     * Hashes every block with index j, so the output depends only on the block and not on its position. Two parties
     * hashing the same block in different batches get the same value.
     */
    BigInteger[] hashByValue(int tweak, byte[][] xs) {
        return hash(tweak, concat(xs), 0);
    }

    /**
     * hashByValue on the consecutive blocks of xs.
     */
    BigInteger[] hashByValue(int tweak, byte[] xs) {
        return hash(tweak, xs, 0);
    }

    private static byte[] concat(byte[][] xs) {
        byte[] input = new byte[xs.length * BLOCK];
        for (int s = 0; s < xs.length; s++) {
            System.arraycopy(xs[s], 0, input, s * BLOCK, BLOCK);
        }
        return input;
    }

    private BigInteger[] hash(int tweak, byte[] input, int stride) {
        int num = input.length / BLOCK;
        byte[] piX = encrypt(input);
        ByteBuffer tweaked = ByteBuffer.allocate(num * blocks * BLOCK);
        for (int s = 0; s < num; s++) {
            for (int j = 0; j < blocks; j++) {
                int offset = (s * blocks + j) * BLOCK;
                tweaked.put(offset, piX, s * BLOCK, BLOCK);
                tweaked.putInt(offset + BLOCK - 2 * Integer.BYTES,
                        tweaked.getInt(offset + BLOCK - 2 * Integer.BYTES) ^ tweak);
                tweaked.putInt(offset + BLOCK - Integer.BYTES,
                        tweaked.getInt(offset + BLOCK - Integer.BYTES) ^ (s * stride + j));
            }
        }
        byte[] output = encrypt(tweaked.array());
        BigInteger[] hashes = new BigInteger[num];
        for (int s = 0; s < num; s++) {
            int offset = s * blocks * BLOCK;
            for (int j = 0; j < blocks; j++) {
                for (int k = 0; k < BLOCK && j * BLOCK + k < byteLength; k++) {
                    output[offset + j * BLOCK + k] ^= piX[s * BLOCK + k];
                }
            }
            hashes[s] = new BigInteger(1, output, offset, byteLength).multiply(p).shiftRight(Byte.SIZE * byteLength);
        }
        return hashes;
    }

    private byte[] encrypt(byte[] input) {
        try {
            return pi.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * a + b mod p for a, b ∈ [0, p). Zp.add reduces with a division; a conditional subtraction suffices.
     */
    static BigInteger add(BigInteger a, BigInteger b, BigInteger p) {
        BigInteger c = a.add(b);
        return c.compareTo(p) >= 0 ? c.subtract(p) : c;
    }

    /**
     * a - b mod p for a, b ∈ [0, p).
     */
    static BigInteger sub(BigInteger a, BigInteger b, BigInteger p) {
        BigInteger c = a.subtract(b);
        return c.signum() < 0 ? c.add(p) : c;
    }
}
