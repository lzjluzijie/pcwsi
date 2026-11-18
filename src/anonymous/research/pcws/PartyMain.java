package anonymous.research.pcws;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.impl.netty.NettyParty;
import edu.alibaba.mpc4j.common.rpc.impl.netty.simple.SimpleNettyRpc;

/**
 * Runs one PC-WSI party in its own process and reports one CSV row per run.
 * <p>
 * Required: --party i (1-based), --parties n, --size m, --topology STAR|RING|TREE|AIDED|LOOKUP. AIDED runs the
 * server-aided two-party protocol alone, with P3 as the server, and needs n = 3. LOOKUP runs the offset-lookup
 * two-party protocol alone and needs n = 2.
 * <p>
 * Optional:
 * <ul>
 *   <li>--result NONE|AIDED|LOOKUP (default AIDED): the two-party protocol that follows a reduction, if any. Not
 *   used with the AIDED and LOOKUP topologies.</li>
 *   <li>--silent: LOOKUP's permute-and-share uses silent OT extension instead of IKNP.</li>
 *   <li>--hosts h_1,...,h_n (default 127.0.0.1 for all) and --port base (default 8800): P_i listens on h_i:base+i-1.</li>
 *   <li>--seed s (default 2025) and --ratio r (default 0.1): see {@link DataGenerator}.</li>
 *   <li>--reps k (default 1): number of runs; all parties synchronize before each run.</li>
 *   <li>--label text (default empty) and --csv file: the label is copied into each row; rows are appended to the file.</li>
 *   <li>--check: P1 compares its output with the ideal functionality and exits with status 1 on a mismatch.</li>
 *   <li>--record dir and --replay dir: run the reduction under that mode of {@link Schedule}, with the times kept in
 *   dir. Not for the AIDED and LOOKUP topologies; --replay needs --result NONE and as many runs recorded.</li>
 * </ul>
 */
public class PartyMain {
    static final String CSV_HEADER = "label,topology,result,silent,parties,size,party,rep,"
            + "reduce_wall_ms,reduce_compute_ms,reduce_sent_bytes,reduce_recv_bytes,"
            + "offline_wall_ms,offline_compute_ms,offline_sent_bytes,offline_recv_bytes,"
            + "total_wall_ms,total_compute_ms,total_sent_bytes,total_recv_bytes,check";
    private static final Set<String> OPTIONS = Set.of("party", "parties", "size", "topology", "result", "silent",
            "hosts", "port", "seed", "ratio", "reps", "label", "csv", "check", "record", "replay");
    private static final Set<String> FLAGS = Set.of("silent", "check");

    public static void main(String[] args) throws Exception {
        Map<String, String> options = parseOptions(args);
        int partyId = Integer.parseInt(required(options, "party")) - 1;
        int parties = Integer.parseInt(required(options, "parties"));
        int size = Integer.parseInt(required(options, "size"));
        Protocol.TopologyType topology = Protocol.TopologyType.valueOf(required(options, "topology"));
        boolean twoParty = topology == Protocol.TopologyType.AIDED || topology == Protocol.TopologyType.LOOKUP;
        Protocol.ResultType result = Protocol.ResultType.valueOf(options.getOrDefault("result",
                twoParty ? "NONE" : "AIDED"));
        String[] hosts = options.containsKey("hosts") ? options.get("hosts").split(",") : null;
        int port = Integer.parseInt(options.getOrDefault("port", "8800"));
        long seed = Long.parseLong(options.getOrDefault("seed", "2025"));
        double ratio = Double.parseDouble(options.getOrDefault("ratio", "0.1"));
        int reps = Integer.parseInt(options.getOrDefault("reps", "1"));
        String label = options.getOrDefault("label", "");
        boolean check = options.containsKey("check");
        boolean silent = options.containsKey("silent");

        if (partyId < 0 || partyId >= parties) {
            throw new IllegalArgumentException("--party must be in [1, " + parties + "]");
        }
        if (hosts != null && hosts.length != parties) {
            throw new IllegalArgumentException("--hosts must list " + parties + " hosts");
        }
        if (twoParty && result != Protocol.ResultType.NONE) {
            throw new IllegalArgumentException("--topology " + topology + " runs no reduction, so it takes no --result");
        }
        if (topology == Protocol.TopologyType.AIDED && parties != 3) {
            throw new IllegalArgumentException("--topology AIDED needs --parties 3");
        }
        if (topology == Protocol.TopologyType.LOOKUP && parties != 2) {
            throw new IllegalArgumentException("--topology LOOKUP needs --parties 2");
        }
        if (options.containsKey("record") && options.containsKey("replay")) {
            throw new IllegalArgumentException("--record and --replay exclude each other");
        }
        if (twoParty && (options.containsKey("record") || options.containsKey("replay"))) {
            throw new IllegalArgumentException("--topology " + topology + " runs no reduction to schedule");
        }
        if (options.containsKey("replay") && result != Protocol.ResultType.NONE) {
            throw new IllegalArgumentException("--replay needs --result NONE");
        }
        if (check && !twoParty && result != Protocol.ResultType.AIDED && result != Protocol.ResultType.LOOKUP) {
            throw new IllegalArgumentException("--check needs P1's output, i.e. --result AIDED|LOOKUP or "
                    + "--topology AIDED|LOOKUP");
        }

        Protocol.Config config = new Protocol.Config.Builder()
                .setParties(parties)
                .setSize(size)
                .setTopologyType(topology)
                .setResultType(result)
                .setSilent(silent)
                .build();

        // In the AIDED and LOOKUP topologies, only P1 and P2 hold inputs
        int holders = twoParty ? 2 : parties;
        Protocol.KeyValuePair[] input = partyId < holders
                ? DataGenerator.generate(seed, parties, size, ratio, config.getUpperBoundM(), partyId)
                : null;
        BigInteger[] expected = null;
        if (check && partyId == 0) {
            Protocol.KeyValuePair[][] inputs = IntStream.range(0, holders)
                    .mapToObj(k -> DataGenerator.generate(seed, parties, size, ratio, config.getUpperBoundM(), k))
                    .toArray(Protocol.KeyValuePair[][]::new);
            expected = DataGenerator.idealWeightSums(inputs);
        }

        Set<NettyParty> partySet = IntStream.range(0, parties)
                .mapToObj(k -> new NettyParty(k, "P_" + (k + 1), hosts == null ? "127.0.0.1" : hosts[k], port + k))
                .collect(Collectors.toSet());
        NettyParty ownParty = partySet.stream().filter(party -> party.getPartyId() == partyId).findFirst()
                .orElseThrow();
        MeteredRpc rpc = new MeteredRpc(new SimpleNettyRpc(ownParty, partySet));
        Party[] otherParties = partySet.stream().filter(party -> party.getPartyId() != partyId).sorted()
                .toArray(Party[]::new);
        Protocol protocol = new Protocol(rpc, config, otherParties);
        if (options.containsKey("record")) {
            protocol.setSchedule(Schedule.Mode.RECORD, Path.of(options.get("record")));
        } else if (options.containsKey("replay")) {
            protocol.setSchedule(Schedule.Mode.REPLAY, Path.of(options.get("replay")));
        }

        rpc.connect();
        boolean pass = true;
        for (int rep = 0; rep < reps; rep++) {
            // Each run starts on a collected heap, so that it does not pay for collecting the garbage of earlier runs.
            // The collection waits until every party has finished, so that it does not hold up a message in flight.
            rpc.synchronize();
            System.gc();
            rpc.synchronize();
            BigInteger[] output = protocol.execute(input);
            String verdict = "";
            if (expected != null) {
                boolean match = Arrays.equals(output, expected);
                pass &= match;
                verdict = match ? "PASS" : "FAIL";
            }
            String row = csvRow(label, config, partyId, rep, protocol, verdict);
            System.out.println(row);
            if (options.containsKey("csv")) {
                appendCsv(Path.of(options.get("csv")), row);
            }
        }
        rpc.disconnect();
        System.exit(pass ? 0 : 1);
    }

    private static String csvRow(String label, Protocol.Config config, int partyId, int rep, Protocol protocol,
                                 String check) {
        return String.join(",", label, config.getTopologyType().name(), config.getResultType().name(),
                String.valueOf(config.isSilent()), String.valueOf(config.getParties()),
                String.valueOf(config.getSize()), String.valueOf(partyId + 1), String.valueOf(rep),
                columns(protocol.getReduction()), columns(protocol.getOffline()), columns(protocol.getTotal()), check);
    }

    private static String columns(Protocol.Phase phase) {
        return String.join(",", ms(phase.wallNanos()), ms(phase.computeNanos()), String.valueOf(phase.sentBytes()),
                String.valueOf(phase.recvBytes()));
    }

    private static String ms(long nanos) {
        return String.format(Locale.ROOT, "%.3f", nanos / 1e6);
    }

    /**
     * Appends a row, writing the header first if the file is empty. Parties may append concurrently.
     */
    private static void appendCsv(Path path, String row) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND);
             FileLock ignored = channel.lock()) {
            String text = (channel.size() == 0 ? CSV_HEADER + "\n" : "") + row + "\n";
            channel.write(ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8)));
        }
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String name = args[i].startsWith("--") ? args[i].substring(2) : "";
            if (!OPTIONS.contains(name)) {
                throw new IllegalArgumentException("Unknown argument: " + args[i]);
            }
            if (FLAGS.contains(name)) {
                options.put(name, "");
            } else if (i + 1 < args.length) {
                options.put(name, args[++i]);
            } else {
                throw new IllegalArgumentException("Missing value for " + args[i]);
            }
        }
        return options;
    }

    private static String required(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing --" + name);
        }
        return value;
    }
}
