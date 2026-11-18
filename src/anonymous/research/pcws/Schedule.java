package anonymous.research.pcws;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;

/**
 * When the parties of a reduction compute, so that the reduction can run on one machine without its parties competing
 * for the CPU. The same configuration runs twice:
 * <ul>
 *   <li>RECORD: the parties compute one at a time. A token goes from party to party in an order where each party comes
 *   after its upstream, with P1 last; a party waits for it before its first heavy computation and passes it on at the
 *   end of its reduction. Each party writes to dir/P&lt;i&gt;.txt one line per run: the compute time of its local
 *   block, which builds the vector it sends or forwards from data it holds before receiving any table, and that of
 *   P2's truncation.</li>
 *   <li>REPLAY: the parties run concurrently. In place of each block a party waits the time recorded for the same
 *   run, and its local block yields a uniformly random vector over Z_p, which is how every masked vector a block
 *   builds is distributed. Everything else runs as usual, so receiving, adding, forwarding and P1's decoding are real
 *   but act on random data.</li>
 * </ul>
 * Waiting for the token is a blocked receive and does not count as compute time; the waits of a replay do. Only the
 * reduction is scheduled: a two-party protocol after it runs as usual and may overlap the turns of later parties.
 */
public final class Schedule {
    public enum Mode {
        NONE, RECORD, REPLAY
    }

    static final Schedule NONE = new Schedule();
    private static final int TOKEN_PTO_ID = 0x20261027;

    private final Mode mode;
    private final MeteredRpc rpc;
    private final Path file;
    // Parties to take the token from and to pass it to, -1 if none
    private final int previous;
    private final int next;
    // REPLAY: the recorded {local, tail} compute times of each run, and the vector a local block starts from
    private final List<long[]> recorded;
    private final BigInteger[] random;
    private int run = -1;
    private long localNanos;
    private long tailNanos;

    private Schedule() {
        mode = Mode.NONE;
        rpc = null;
        file = null;
        previous = -1;
        next = -1;
        recorded = null;
        random = null;
    }

    Schedule(Mode mode, Path dir, MeteredRpc rpc, Protocol.TopologyType topology, int parties, int length,
             BigInteger p) throws IOException {
        this.mode = mode;
        this.rpc = rpc;
        int partyId = rpc.ownParty().getPartyId();
        file = dir.resolve("P" + (partyId + 1) + ".txt");
        // Ring: P2, P3, ..., Pn, P1. Tree: children have larger ids. Star: any order ending with P1.
        int[] order = topology == Protocol.TopologyType.RING
                ? IntStream.concat(IntStream.range(1, parties), IntStream.of(0)).toArray()
                : IntStream.iterate(parties - 1, k -> k >= 0, k -> k - 1).toArray();
        int position = IntStream.range(0, parties).filter(k -> order[k] == partyId).findFirst().orElseThrow();
        previous = position > 0 ? order[position - 1] : -1;
        next = position < parties - 1 ? order[position + 1] : -1;
        if (mode == Mode.RECORD) {
            Files.createDirectories(dir);
            Files.deleteIfExists(file);
            recorded = null;
            random = null;
        } else {
            recorded = Files.readAllLines(file).stream()
                            .map(line -> Arrays.stream(line.split(" ")).mapToLong(Long::parseLong).toArray())
                            .toList();
            SecureRandom secureRandom = new SecureRandom();
            random = IntStream.range(0, length).mapToObj(i -> BigIntegerUtils.randomNonNegative(p, secureRandom))
                              .toArray(BigInteger[]::new);
        }
    }

    /**
     * Starts the next run.
     */
    void begin() {
        run++;
        localNanos = 0;
        tailNanos = 0;
        if (mode == Mode.REPLAY && run >= recorded.size()) {
            throw new IllegalStateException(file + " records only " + recorded.size() + " runs");
        }
    }

    /**
     * RECORD: waits for the token.
     */
    void awaitTurn() {
        if (mode == Mode.RECORD && previous >= 0) {
            rpc.receive(tokenHeader(previous, rpc.ownParty().getPartyId()));
        }
    }

    /**
     * The local block, which must not receive anything.
     */
    BigInteger[] local(Supplier<BigInteger[]> block) {
        return switch (mode) {
            case NONE -> block.get();
            case RECORD -> {
                long start = computeNanos();
                BigInteger[] vector = block.get();
                localNanos = computeNanos() - start;
                yield vector;
            }
            case REPLAY -> {
                long deadline = System.nanoTime() + recorded.get(run)[0];
                BigInteger[] vector = random.clone();
                waitUntil(deadline);
                yield vector;
            }
        };
    }

    /**
     * P2's truncation, which must not receive anything.
     */
    void tail(Runnable block) {
        switch (mode) {
            case NONE -> block.run();
            case RECORD -> {
                long start = computeNanos();
                block.run();
                tailNanos = computeNanos() - start;
            }
            case REPLAY -> waitUntil(System.nanoTime() + recorded.get(run)[1]);
        }
    }

    /**
     * RECORD: writes the times of this run, frees the heap and passes the token on, all outside the measured phases.
     */
    void endTurn() throws IOException {
        if (mode != Mode.RECORD) {
            return;
        }
        Files.writeString(file, localNanos + " " + tailNanos + "\n", StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
        System.gc();
        if (next >= 0) {
            rpc.send(DataPacket.fromByteArrayList(tokenHeader(rpc.ownParty().getPartyId(), next), List.of()));
        }
    }

    private DataPacketHeader tokenHeader(int sender, int receiver) {
        return new DataPacketHeader(0, TOKEN_PTO_ID, 0, run, sender, receiver);
    }

    private long computeNanos() {
        return System.nanoTime() - rpc.getWaitNanos();
    }

    private static void waitUntil(long deadline) {
        for (long left = deadline - System.nanoTime(); left > 0; left = deadline - System.nanoTime()) {
            LockSupport.parkNanos(left);
        }
    }
}
