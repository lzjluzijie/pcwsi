# Emulated networks for running the parties on one machine. Sourced by run-local.sh.
#
# Party i runs in its own network namespace with address 10.0.0.i on a veth attached to a bridge in the namespace of
# the calling script. LAN leaves the links unshaped. Both WAN settings delay every packet by $DELAY (default 40ms) at
# the sender, so a round trip takes twice that, and limit each direction to $RATE (default 100mbit):
#   WAN-L: per ordered pair of parties, with one HTB class per destination on the sender's veth;
#   WAN-N: per party, with HTB on the sender's veth (upload) and on the bridge port towards it (download).
# Only IP packets are shaped, so ARP is not delayed.
# No root is needed: the calling script re-runs itself as root of a new user namespace.

# Re-runs the calling script in new user, network, mount and PID namespaces, unless it already runs there. Every
# process left in them is killed when the script exits.
net_enter() {
  if [[ -z ${PCWS_NETNS:-} ]]; then
    PCWS_NETNS=1 exec unshare --user --map-root-user --net --pid --fork --kill-child --mount-proc "$0" "$@"
  fi
}

# net_setup <LAN|WAN-L|WAN-N> <parties>: creates the namespaces and links, and sets NET_HOSTS to the parties'
# addresses separated by commas.
net_setup() {
  local net=$1 n=$2 rate=${RATE:-100mbit} delay=${DELAY:-40ms} i j
  case $net in
    LAN | WAN-L | WAN-N) ;;
    *) echo "unknown network $net, expected LAN, WAN-L or WAN-N" >&2; return 1 ;;
  esac

  ip link add br0 type bridge
  ip link set br0 up
  NET_PIDS=() NET_HOSTS=
  for ((i = 1; i <= n; i++)); do
    unshare --net sleep infinity &
    NET_PIDS[i]=$!
    # The child creates its namespace after the fork, so wait for it before moving a device there
    while [[ $(readlink "/proc/${NET_PIDS[i]}/ns/net") == $(readlink /proc/self/ns/net) ]]; do
      sleep 0.01
    done
    NET_HOSTS+=${NET_HOSTS:+,}10.0.0.$i
    ip link add "v$i" type veth peer name eth0 netns "${NET_PIDS[i]}"
    ip link set "v$i" master br0 up
    net_in "$i" ip link set lo up
    net_in "$i" ip addr add "10.0.0.$i/24" dev eth0
    net_in "$i" ip link set eth0 up
  done

  for ((i = 1; i <= n; i++)); do
    case $net in
      WAN-L)
        net_in "$i" tc qdisc add dev eth0 root handle 1: htb r2q 1000
        for ((j = 1; j <= n; j++)); do
          if ((j != i)); then
            net_in "$i" tc class add dev eth0 parent 1: classid "1:$j" htb rate "$rate"
            net_in "$i" tc qdisc add dev eth0 parent "1:$j" netem delay "$delay"
            net_in "$i" tc filter add dev eth0 parent 1: protocol ip u32 match ip dst "10.0.0.$j/32" flowid "1:$j"
          fi
        done
        ;;
      WAN-N)
        net_in "$i" tc qdisc add dev eth0 root handle 1: htb r2q 1000
        net_in "$i" tc class add dev eth0 parent 1: classid 1:1 htb rate "$rate"
        net_in "$i" tc qdisc add dev eth0 parent 1:1 netem delay "$delay"
        net_in "$i" tc filter add dev eth0 parent 1: protocol ip u32 match u32 0 0 flowid 1:1
        tc qdisc add dev "v$i" root handle 1: htb r2q 1000
        tc class add dev "v$i" parent 1: classid 1:1 htb rate "$rate"
        tc filter add dev "v$i" parent 1: protocol ip u32 match u32 0 0 flowid 1:1
        ;;
    esac
  done
}

# net_in <party> <command...>: runs the command in the party's network namespace.
net_in() {
  local i=$1
  shift
  nsenter --target "${NET_PIDS[i]}" --net "$@"
}
