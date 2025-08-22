package anonymous.research.pcws;

import java.math.BigInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.RpcManager;
import edu.alibaba.mpc4j.common.rpc.impl.netty.NettyRpcManager;

public class ProtocolTest {

    public static void main(String[] args) throws InterruptedException {
        if (args.length == 0) {
            runStandardBench();
        } else if (args.length == 1) {
            runAidedBench();
        } else if (args.length == 2) {
            int numParties = Integer.parseInt(args[0]);
            int size = Integer.parseInt(args[1]);
            runTest(new Protocol.Config.Builder()
                    .setParties(numParties)
                    .setSize(size)
                    .setTopologyType(Protocol.TopologyType.STAR)
                    .setResultType(Protocol.ResultType.AIDED)
                    .setDebug(true)
                    .build());
        } else {
            System.out.println("Usage: java ProtocolTest [<parties> <size>]");
            System.out.println("No args: run standard benchmark");
            System.out.println("Example: java ProtocolTest 8 1048576");
        }
        System.exit(0);
    }

    public static void runStandardBench() throws InterruptedException {
        int[] parties = {8, 4, 3};
        int[] sizes = {1048576, 65536, 4096};

        System.out.println("Running standard benchmark...");
        System.out.println("=".repeat(60));

        for (int size : sizes) {
            for (int numParties : parties) {
                System.out.println("\n\n\n\n\n");
                System.out.printf("\n[BENCHMARK] Parties: %d, Size: %d%n",
                        numParties, size);
                System.out.println("-".repeat(40));

                runTest(new Protocol.Config.Builder()
                        .setParties(numParties)
                        .setSize(size)
                        .setTopologyType(Protocol.TopologyType.STAR)
                        .setResultType(Protocol.ResultType.NONE)
                        .build());

                System.out.println("=".repeat(60));
                Thread.sleep(5000);
            }
        }

        System.out.println("\nStandard benchmark completed!");
    }

    public static void runAidedBench() throws InterruptedException {
        int[] sizes = {1048576, 65536, 4096};

        System.out.println("Running aided benchmark...");
        System.out.println("=".repeat(60));

        for (int size : sizes) {
            System.out.println("\n\n\n\n\n");
            System.out.printf("\n[BENCHMARK] Aided size: %d\n", size);
            System.out.println("-".repeat(40));

            runTest(new Protocol.Config.Builder()
                    .setParties(3)
                    .setSize(size)
                    .setTopologyType(Protocol.TopologyType.AIDED)
                    .setResultType(Protocol.ResultType.NONE)
                    .build());

            System.out.println("=".repeat(60));
            Thread.sleep(5000);
        }

        System.out.println("\nAided benchmark completed!");
    }

    public static void runTest(Protocol.Config config) {
        System.out.println("Starting PCWS Protocol Test...");
        int numParties = config.getParties();
        System.out.println("Testing with " + numParties + " parties and " + config.getSize() + " items per party");

//        RpcManager rpcManager = new MemoryRpcManager(numParties);
        RpcManager rpcManager = new NettyRpcManager(numParties, 8800);

        // Get RPC instances for each party
        Rpc[] rpcs = new Rpc[numParties];
        for (int k = 0; k < numParties; k++) {
            rpcs[k] = rpcManager.getRpc(k);
        }

        try {
            // Connect all parties
            for (int i = 0; i < numParties; i++) {
                new Thread(rpcs[i]::connect).start();
                Thread.sleep(100);
            }

            System.out.println("RPC connections established");

            // Generate test data with overlapping keys
            Protocol.KeyValuePair[][] inputs = new Protocol.KeyValuePair[numParties][];
            for (int i = 0; i < numParties; i++) {
                inputs[i] = generateTestDataWithOverlap(i, config.getSize(), i);
            }

            if (config.isDebug()) {
                System.out.println("Test data generated:");
                for (int i = 0; i < numParties; i++) {
                    System.out.println("P" + (i + 1) + ": " + formatPairs(inputs[i], 5));
                }

                // Show overlapping keys
                System.out.println("\nOverlapping keys (first 16 items):");
                for (int i = 0; i < 16; i++) {
                    System.out.printf("Item %d: ", i);
                    for (int p = 0; p < numParties; p++) {
                        System.out.printf("P%d=%d ", p + 1, inputs[p][i].key());
                    }
                    System.out.println();
                }
            } else {
                System.out.println("Test data generated (" + config.getSize() + " items per party)");
            }

            // Create protocols
            Protocol[] protocols = new Protocol[numParties];
            for (int i = 0; i < numParties; i++) {
                // Create other parties array (excluding current party)
                edu.alibaba.mpc4j.common.rpc.Party[] otherParties = new edu.alibaba.mpc4j.common.rpc.Party[numParties - 1];
                int idx = 0;
                for (int j = 0; j < numParties; j++) {
                    if (j != i) {
                        otherParties[idx++] = rpcs[j].getParty(j);
                    }
                }
                protocols[i] = new Protocol(rpcs[i], config, otherParties);
            }

            // Synchronization
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch endLatch = new CountDownLatch(numParties);

            // Create executor
            ExecutorService executor = Executors.newFixedThreadPool(numParties);

            // Submit tasks
            for (int i = 0; i < numParties; i++) {
                final int partyId = i;
                executor.submit(() -> {
                    executeParty(partyId, protocols[partyId], inputs[partyId], startLatch, endLatch);
                    if (partyId < 3) {
                        System.out.println("Party " + partyId + " sent: " + formatBytes(rpcs[partyId].getPayloadByteLength()));
//                        System.out.println("Party " + partyId + " received: " + formatBytes(rpcs[partyId].getReceiveByteLength()));
                    }
                    rpcs[partyId].disconnect();
                });
            }

            // Start execution
            System.out.println("\nStarting protocol execution...");
            startLatch.countDown();

            // Wait for completion
            endLatch.await();
            System.out.println("\nProtocol execution completed successfully!");

            // Cleanup
            executor.shutdown();
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
//        finally {
//            for (int i = 0; i < numParties; i++) {
//                new Thread(rpcs[i]::disconnect).start();
//            }
//        }
    }

    private static void executeParty(int partyId, Protocol protocol, lu.halu.research.pcws.Protocol.KeyValuePair[] input,
                                     CountDownLatch startLatch, CountDownLatch endLatch) {
        try {
            startLatch.await();
//            System.out.println("Party " + partyId + " executing...");

            if (protocol.getConfig().getTopologyType().equals(Protocol.TopologyType.AIDED)) {
                BigInteger[] keys = convertToKeys(input);
                BigInteger[] values = convertToValues(input);

                long startTime = System.currentTimeMillis();
                switch (partyId) {
                    case 0 -> protocol.runAidedP1(keys, values);
                    case 1 -> protocol.runAidedP2(keys, values);
                    case 2 -> protocol.runAidedServer();
                }
                long endTime = System.currentTimeMillis();
                System.out.println("Party " + partyId + " completed in " + (endTime - startTime) + "ms");
            } else {
                long startTime = System.currentTimeMillis();
                protocol.execute(input);
                long endTime = System.currentTimeMillis();
                System.out.println("Party " + partyId + " completed in " + (endTime - startTime) + "ms");
            }
        } catch (Exception e) {
            System.err.println("Party " + partyId + " failed: " + e.getMessage());
            e.printStackTrace();
        } finally {
            endLatch.countDown();
        }
    }

    /**
     * Generate test data with overlapping keys
     *
     * @param partyId       The party ID
     * @param count         Number of items to generate
     * @param overlapOffset Offset for overlapping keys
     * @return Array of KeyValuePair with overlapping keys
     */
    private static Protocol.KeyValuePair[] generateTestDataWithOverlap(int partyId, int count, int overlapOffset) {
        Protocol.KeyValuePair[] pairs = new Protocol.KeyValuePair[count];

        // Generate overlapping keys for first 8 items
        for (int i = 0; i < 8; i++) {
            long itemKey = i;
            long value = partyId * 100L + i;
            pairs[i] = new Protocol.KeyValuePair(itemKey, value);
        }

        // Generate unique keys for remaining items
        for (int i = 8; i < count; i++) {
            // Each party gets unique keys starting from different offsets
            long itemKey = 1000 + partyId * 1000000L + i;
            long value = partyId * 100L + i;
            pairs[i] = new Protocol.KeyValuePair(itemKey, value);
        }

        return pairs;
    }

    /**
     * Format pairs for display (showing only first n items)
     */
    private static String formatPairs(Protocol.KeyValuePair[] pairs, int maxItems) {
        StringBuilder sb = new StringBuilder("[");
        int itemsToShow = Math.min(maxItems, pairs.length);
        for (int i = 0; i < itemsToShow; i++) {
            if (i > 0) sb.append(", ");
            sb.append(pairs[i].key()).append(":").append(pairs[i].value());
        }
        if (pairs.length > maxItems) {
            sb.append(", ... (").append(pairs.length - maxItems).append(" more)");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Format pairs for display (showing all items)
     */
    private static String formatPairs(Protocol.KeyValuePair[] pairs) {
        return formatPairs(pairs, pairs.length);
    }

    public static String formatBytes(long bytes) {
        return String.format("%d Bytes, %.2f KiB, %.2f MiB", bytes, bytes / 1024.0, bytes / 1024.0 / 1024.0);
    }

    private static BigInteger[] convertToKeys(Protocol.KeyValuePair[] input) {
        BigInteger[] keys = new BigInteger[input.length];
        for (int i = 0; i < input.length; i++) {
            keys[i] = BigInteger.valueOf(input[i].key());
        }
        return keys;
    }

    private static BigInteger[] convertToValues(Protocol.KeyValuePair[] input) {
        BigInteger[] values = new BigInteger[input.length];
        for (int i = 0; i < input.length; i++) {
            values[i] = BigInteger.valueOf(input[i].value());
        }
        return values;
    }
} 