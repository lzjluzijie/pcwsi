package anonymous.research.pcws;

import static anonymous.research.pcws.ZpHash.add;
import static anonymous.research.pcws.ZpHash.sub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.Zp;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpFactory;
import edu.alibaba.mpc4j.common.tool.network.benes.BenesNetwork;
import edu.alibaba.mpc4j.common.tool.network.benes.BenesNetworkFactory;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.BlockUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotReceiver;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotReceiverOutput;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotSender;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotSenderOutput;

/**
 * Permute-and-share over Z_p between a vector holder (sender) and a permutation holder (receiver), semi-honest.
 * <p>
 * Inputs: the sender holds z ∈ Z_p^N and the receiver holds a permutation π on [N], N ≥ 2. Outputs: the sender gets a
 * and the receiver gets b, uniformly random subject to a[π(i)] + b[π(i)] = z[i] for all i.
 * <p>
 * Offline (independent of z): the parties run an oblivious switching network over a Beneš network routed by the
 * receiver, on a random vector ρ chosen by the sender. The sender gets α and the receiver gets β with
 * α[π(i)] + β[π(i)] = ρ[i]. The network has 2⌈log N⌉ - 1 layers. Each switch takes one correlated OT and one Z_p
 * correction from the sender, and the sender never waits for the receiver outside the OT extension. The receiver
 * requests the OTs of the next layer before processing the current one, so the two parties' layers overlap.
 * <p>
 * Online: one message. The sender sends d = z - ρ and outputs a = α; the receiver outputs b[π(i)] = β[π(i)] + d[i].
 * Each offline run serves one online run.
 */
public class PermuteShare {
    // Gate value of mpc4j's Beneš network for a position without a switch
    private static final byte EMPTY_GATE = 2;

    private PermuteShare() {
        // empty
    }

    private enum PtoStep {
        SENDER_SEND_SWITCH_CORRECTIONS,
        SENDER_SEND_MASKED_INPUT,
    }

    /**
     * Configuration shared by both parties.
     */
    public static class Config extends AbstractMultiPartyPtoConfig {
        private final CotConfig cotConfig;

        /**
         * @param silent whether the correlated OTs come from silent OT extension instead of IKNP.
         */
        public Config(boolean silent) {
            this(CotFactory.createDefaultConfig(SecurityModel.SEMI_HONEST, silent));
        }

        private Config(CotConfig cotConfig) {
            super(SecurityModel.SEMI_HONEST, cotConfig);
            this.cotConfig = cotConfig;
        }
    }

    /**
     * The vector holder.
     */
    public static class Sender extends AbstractTwoPartyPto {
        private final CotSender cotSender;
        private Zp zp;
        private ZpHash zpHash;
        private int byteLength;
        // Offline correlation for the next online run
        private BigInteger[] rho;
        private BigInteger[] alpha;

        public Sender(Rpc rpc, Party receiverParty, Config config) {
            super(PermuteSharePtoDesc.getInstance(), rpc, receiverParty, config);
            cotSender = CotFactory.createSender(rpc, receiverParty, config.cotConfig);
            addSubPto(cotSender);
        }

        public void init(BigInteger p) throws MpcAbortException {
            zp = ZpFactory.createInstance(envType, p);
            byteLength = CommonUtils.getByteLength(p.bitLength());
            zpHash = new ZpHash(p);
            cotSender.init(BlockUtils.randomBlock(secureRandom));
            initState();
        }

        /**
         * Prepares the correlation for one online run on vectors of length num.
         */
        public void offline(int num) throws MpcAbortException {
            checkInitialized();
            MathPreconditions.checkGreater("num", num, 1);
            // The topology does not depend on the permutation, so the sender builds it from the identity
            BenesNetwork<BigInteger> network = BenesNetworkFactory.createInstance(envType,
                    IntStream.range(0, num).toArray());
            int[][] switchIndexes = network.getLayerSwitchIndexes();
            int[][] layerInputs = network.getFixedLayerPermutations();
            BigInteger p = zp.getPrime();

            rho = IntStream.range(0, num).mapToObj(i -> zp.createRandom(secureRandom)).toArray(BigInteger[]::new);
            BigInteger[] wires = rho;
            for (int layer = 0; layer < network.getLevel(); layer++) {
                boolean[] switches = switches(switchIndexes[layer], network.getGates(layer));
                int[] input = layerInputs[layer];
                CotSenderOutput cot = cotSender.send(countSwitches(switches));
                BigInteger[] r0 = zpHash.hash(layer, cot.getR0Array());
                BigInteger[] r1 = zpHash.hash(layer, cot.getR1Array());
                List<byte[]> corrections = new ArrayList<>(cot.getNum());
                BigInteger[] next = new BigInteger[num];
                int s = 0;
                for (int i = 0; i < num; i++) {
                    if (!switches[i]) {
                        next[i] = wires[input[i]];
                    } else {
                        BigInteger top = wires[input[i - 1]];
                        BigInteger bottom = wires[input[i]];
                        BigInteger r = r0[s];
                        // The receiver gets r with choice 0 and r + bottom - top with choice 1
                        BigInteger correction = sub(add(r, sub(bottom, top, p), p), r1[s], p);
                        corrections.add(BigIntegerUtils.nonNegBigIntegerToByteArray(correction, byteLength));
                        next[i - 1] = sub(top, r, p);
                        next[i] = add(bottom, r, p);
                        s++;
                    }
                }
                sendOtherPartyEqualSizePayload(PtoStep.SENDER_SEND_SWITCH_CORRECTIONS.ordinal(), corrections);
                wires = next;
            }
            alpha = wires;
        }

        /**
         * Returns a with a[π(i)] + b[π(i)] = z[i], consuming the offline correlation.
         */
        public BigInteger[] online(BigInteger[] z) {
            checkInitialized();
            if (rho == null) {
                throw new IllegalStateException("offline() must run before each online()");
            }
            MathPreconditions.checkEqual("z.length", "num", z.length, rho.length);
            BigInteger p = zp.getPrime();
            List<byte[]> masked = IntStream.range(0, z.length)
                    .mapToObj(i -> BigIntegerUtils.nonNegBigIntegerToByteArray(sub(z[i], rho[i], p), byteLength))
                    .toList();
            sendOtherPartyEqualSizePayload(PtoStep.SENDER_SEND_MASKED_INPUT.ordinal(), masked);
            BigInteger[] a = alpha;
            rho = null;
            alpha = null;
            return a;
        }
    }

    /**
     * The permutation holder.
     */
    public static class Receiver extends AbstractTwoPartyPto {
        private final CotReceiver cotReceiver;
        private Zp zp;
        private ZpHash zpHash;
        private int byteLength;
        // Offline correlation for the next online run
        private int[] inversePi;
        private BigInteger[] beta;

        public Receiver(Rpc rpc, Party senderParty, Config config) {
            super(PermuteSharePtoDesc.getInstance(), rpc, senderParty, config);
            cotReceiver = CotFactory.createReceiver(rpc, senderParty, config.cotConfig);
            addSubPto(cotReceiver);
        }

        public void init(BigInteger p) throws MpcAbortException {
            zp = ZpFactory.createInstance(envType, p);
            byteLength = CommonUtils.getByteLength(p.bitLength());
            zpHash = new ZpHash(p);
            cotReceiver.init();
            initState();
        }

        /**
         * Prepares the correlation for one online run with permutation pi, where pi[i] = π(i).
         */
        public void offline(int[] pi) throws MpcAbortException {
            checkInitialized();
            int num = pi.length;
            MathPreconditions.checkGreater("num", num, 1);
            inversePi = new int[num];
            Arrays.fill(inversePi, -1);
            for (int i = 0; i < num; i++) {
                if (pi[i] < 0 || pi[i] >= num || inversePi[pi[i]] != -1) {
                    throw new IllegalArgumentException("pi is not a permutation on [" + num + "]");
                }
                inversePi[pi[i]] = i;
            }
            // Output position k of the network carries input inversePi[k], so input i lands at π(i)
            BenesNetwork<BigInteger> network = BenesNetworkFactory.createInstance(envType, inversePi);
            int[][] switchIndexes = network.getLayerSwitchIndexes();
            int[][] layerInputs = network.getFixedLayerPermutations();
            int level = network.getLevel();
            BigInteger p = zp.getPrime();

            BigInteger[] wires = new BigInteger[num];
            Arrays.fill(wires, BigInteger.ZERO);
            boolean[] switches = switches(switchIndexes[0], network.getGates(0));
            boolean[] choices = choices(switches, switchIndexes[0], network.getGates(0));
            CotReceiverOutput cot = cotReceiver.receive(choices);
            for (int layer = 0; layer < level; layer++) {
                int[] input = layerInputs[layer];
                boolean[] nextSwitches = null;
                boolean[] nextChoices = null;
                CotReceiverOutput nextCot = null;
                if (layer + 1 < level) {
                    nextSwitches = switches(switchIndexes[layer + 1], network.getGates(layer + 1));
                    nextChoices = choices(nextSwitches, switchIndexes[layer + 1], network.getGates(layer + 1));
                    nextCot = cotReceiver.receive(nextChoices);
                }
                BigInteger[] rb = zpHash.hash(layer, cot.getRbArray());
                List<byte[]> corrections = receiveOtherPartyEqualSizePayload(
                        PtoStep.SENDER_SEND_SWITCH_CORRECTIONS.ordinal(), choices.length, byteLength);
                BigInteger[] next = new BigInteger[num];
                int s = 0;
                for (int i = 0; i < num; i++) {
                    if (!switches[i]) {
                        next[i] = wires[input[i]];
                    } else {
                        BigInteger top = wires[input[i - 1]];
                        BigInteger bottom = wires[input[i]];
                        BigInteger w = rb[s];
                        if (choices[s]) {
                            w = add(w, BigIntegerUtils.byteArrayToNonNegBigInteger(corrections.get(s)), p);
                            next[i - 1] = add(bottom, w, p);
                            next[i] = sub(top, w, p);
                        } else {
                            next[i - 1] = add(top, w, p);
                            next[i] = sub(bottom, w, p);
                        }
                        s++;
                    }
                }
                wires = next;
                switches = nextSwitches;
                choices = nextChoices;
                cot = nextCot;
            }
            beta = wires;
        }

        /**
         * Returns b with a[π(i)] + b[π(i)] = z[i], consuming the offline correlation.
         */
        public BigInteger[] online() {
            checkInitialized();
            if (beta == null) {
                throw new IllegalStateException("offline() must run before each online()");
            }
            int num = beta.length;
            List<byte[]> masked = receiveOtherPartyEqualSizePayload(PtoStep.SENDER_SEND_MASKED_INPUT.ordinal(), num,
                    byteLength);
            BigInteger p = zp.getPrime();
            BigInteger[] b = new BigInteger[num];
            for (int k = 0; k < num; k++) {
                b[k] = add(beta[k], BigIntegerUtils.byteArrayToNonNegBigInteger(masked.get(inversePi[k])), p);
            }
            inversePi = null;
            beta = null;
            return b;
        }

        /**
         * Choice bits of the switches in a layer, in the order the sender consumes the OTs.
         */
        private static boolean[] choices(boolean[] switches, int[] switchIndex, byte[] gates) {
            boolean[] choices = new boolean[countSwitches(switches)];
            int s = 0;
            for (int i = 0; i < switches.length; i++) {
                if (switches[i]) {
                    choices[s++] = gates[switchIndex[i]] == 1;
                }
            }
            return choices;
        }
    }

    /**
     * Marks the positions i that close a switch of a layer: i shares its switch index with i - 1, and the gate is not
     * empty. mpc4j gives the empty gates that pad two-wire subnetworks a switch index too. They depend only on the
     * number of wires, so both parties skip the same ones.
     */
    private static boolean[] switches(int[] switchIndex, byte[] gates) {
        boolean[] switches = new boolean[switchIndex.length];
        for (int i = 1; i < switchIndex.length; i++) {
            switches[i] = switchIndex[i] != -1 && switchIndex[i] == switchIndex[i - 1]
                    && gates[switchIndex[i]] != EMPTY_GATE;
        }
        return switches;
    }

    private static int countSwitches(boolean[] switches) {
        int count = 0;
        for (boolean isSwitch : switches) {
            if (isSwitch) {
                count++;
            }
        }
        return count;
    }

    /**
     * Protocol description
     */
    private static class PermuteSharePtoDesc implements PtoDesc {
        private static final int PTO_ID = 0x20261025;
        private static final String PTO_NAME = "PCWS_ZP_PERMUTE_SHARE";
        private static final PermuteSharePtoDesc INSTANCE = new PermuteSharePtoDesc();

        private PermuteSharePtoDesc() {
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
