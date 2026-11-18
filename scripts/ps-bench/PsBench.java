import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.rpc.impl.netty.NettyParty;
import edu.alibaba.mpc4j.common.rpc.impl.netty.simple.SimpleNettyRpc;
import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkUtils;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import anonymous.research.pcws.PermuteShare;

// Usage: PsBench <role 0=sender|1=receiver> <m> <silent> <port> <reps> [check]; N = ⌈1.27m⌉, p = nextPrime(3mNM·2^40)
public class PsBench {
    public static void main(String[] args) throws Exception {
        int role = Integer.parseInt(args[0]);
        int m = Integer.parseInt(args[1]);
        int num = (int) Math.ceil(1.27 * m);
        BigInteger p = BigInteger.valueOf(3L * m * num).multiply(BigInteger.valueOf(1_000_000)).shiftLeft(40)
                .nextProbablePrime();
        boolean silent = Boolean.parseBoolean(args[2]);
        int port = Integer.parseInt(args[3]);
        int reps = Integer.parseInt(args[4]);
        boolean check = args.length > 5 && args[5].equals("check");
        int byteLength = CommonUtils.getByteLength(p.bitLength());

        NettyParty s = new NettyParty(0, "S", "127.0.0.1", port);
        NettyParty r = new NettyParty(1, "R", "127.0.0.1", port + 1);
        SimpleNettyRpc rpc = new SimpleNettyRpc(role == 0 ? s : r, Set.of(s, r));
        Party other = role == 0 ? r : s;
        PermuteShare.Config config = new PermuteShare.Config(silent);
        SecureRandom rnd = new SecureRandom();
        rpc.connect();

        PermuteShare.Sender sender = role == 0 ? new PermuteShare.Sender(rpc, other, config) : null;
        PermuteShare.Receiver receiver = role == 1 ? new PermuteShare.Receiver(rpc, other, config) : null;
        String tag = String.format(Locale.ROOT, "%s,%d,%d,%s", role == 0 ? "sender" : "receiver", num, p.bitLength(),
                silent ? "silent" : "iknp");

        rpc.synchronize();
        long bytes = rpc.getPayloadByteLength();
        long t = System.nanoTime();
        if (role == 0) sender.init(p); else receiver.init(p);
        report(tag, -1, "init", t, bytes, rpc);

        for (int rep = 0; rep < reps; rep++) {
            BigInteger[] z = null;
            int[] pi = null;
            if (role == 0) {
                z = IntStream.range(0, num).mapToObj(i -> new BigInteger(p.bitLength() + 40, rnd).mod(p))
                        .toArray(BigInteger[]::new);
            } else {
                pi = PermutationNetworkUtils.randomPermutation(num, rnd);
            }
            rpc.synchronize();
            bytes = rpc.getPayloadByteLength();
            t = System.nanoTime();
            if (role == 0) sender.offline(num); else receiver.offline(pi);
            report(tag, rep, "offline", t, bytes, rpc);

            rpc.synchronize();
            bytes = rpc.getPayloadByteLength();
            t = System.nanoTime();
            BigInteger[] out = role == 0 ? sender.online(z) : receiver.online();
            report(tag, rep, "online", t, bytes, rpc);

            if (check) {
                DataPacketHeader piHeader = new DataPacketHeader(99, 0x7eee, 2 * rep, 1, 0);
                DataPacketHeader bHeader = new DataPacketHeader(99, 0x7eee, 2 * rep + 1, 1, 0);
                if (role == 1) {
                    ByteBuffer buffer = ByteBuffer.allocate(4 * num);
                    for (int v : pi) buffer.putInt(v);
                    rpc.send(DataPacket.fromByteArrayList(piHeader, List.of(buffer.array())));
                    List<byte[]> payload = new ArrayList<>(num);
                    for (BigInteger v : out) payload.add(BigIntegerUtils.nonNegBigIntegerToByteArray(v, byteLength));
                    rpc.send(DataPacket.fromByteArrayList(bHeader, payload));
                } else {
                    ByteBuffer buffer = ByteBuffer.wrap(rpc.receive(piHeader).getPayload().get(0));
                    List<byte[]> payload = rpc.receive(bHeader).getPayload();
                    int masked = 0;
                    for (int i = 0; i < num; i++) {
                        int k = buffer.getInt();
                        BigInteger a = out[k];
                        BigInteger b = BigIntegerUtils.byteArrayToNonNegBigInteger(payload.get(k));
                        if (a.signum() < 0 || a.compareTo(p) >= 0 || b.compareTo(p) >= 0
                                || !a.add(b).mod(p).equals(z[i])) {
                            throw new IllegalStateException("F_PS mismatch at " + i);
                        }
                        if (!a.equals(z[i])) masked++;
                    }
                    System.out.println(tag + "," + rep + ",check,PASS,masked=" + masked);
                }
            }
        }
        rpc.disconnect();
        System.exit(0);
    }

    private static void report(String tag, int rep, String phase, long start, long bytesAtStart, SimpleNettyRpc rpc) {
        System.out.printf(Locale.ROOT, "%s,%d,%s,%.1f,%d%n", tag, rep, phase, (System.nanoTime() - start) / 1e6,
                rpc.getPayloadByteLength() - bytesAtStart);
    }
}
