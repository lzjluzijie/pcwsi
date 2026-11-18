package anonymous.research.pcws;

import java.util.Set;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;

/**
 * Delegates to an Rpc and also counts the payload bytes received and the time spent blocked in receive. Every
 * receive goes through here, including those of mpc4j sub-protocols, so compute time is wall time minus wait time.
 */
public final class MeteredRpc implements Rpc {
    private final Rpc rpc;
    private long waitNanos;
    private long receivedByteLength;

    public MeteredRpc(Rpc rpc) {
        this.rpc = rpc;
    }

    public long getWaitNanos() {
        return waitNanos;
    }

    public long getReceivedByteLength() {
        return receivedByteLength;
    }

    @Override
    public DataPacket receive(DataPacketHeader header) {
        long start = System.nanoTime();
        DataPacket packet = rpc.receive(header);
        count(start, packet);
        return packet;
    }

    @Override
    public DataPacket receiveAny(int ptoId) {
        long start = System.nanoTime();
        DataPacket packet = rpc.receiveAny(ptoId);
        count(start, packet);
        return packet;
    }

    private void count(long start, DataPacket packet) {
        waitNanos += System.nanoTime() - start;
        if (packet != null) {
            receivedByteLength += packet.getPayload().stream().mapToLong(data -> data.length).sum();
        }
    }

    @Override
    public Party ownParty() {
        return rpc.ownParty();
    }

    @Override
    public Set<Party> getPartySet() {
        return rpc.getPartySet();
    }

    @Override
    public Party getParty(int partyId) {
        return rpc.getParty(partyId);
    }

    @Override
    public void connect() {
        rpc.connect();
    }

    @Override
    public void send(DataPacket dataPacket) {
        rpc.send(dataPacket);
    }

    @Override
    public long getPayloadByteLength() {
        return rpc.getPayloadByteLength();
    }

    @Override
    public long getSendByteLength() {
        return rpc.getSendByteLength();
    }

    @Override
    public long getSendDataPacketNum() {
        return rpc.getSendDataPacketNum();
    }

    @Override
    public void synchronize() {
        rpc.synchronize();
    }

    @Override
    public void reset() {
        rpc.reset();
    }

    @Override
    public void disconnect() {
        rpc.disconnect();
    }
}
