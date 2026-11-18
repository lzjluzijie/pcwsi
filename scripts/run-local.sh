#!/usr/bin/env bash
# Runs one PC-WSI instance on this machine with every party in its own JVM.
# Usage: [NET=LAN|WAN-L|WAN-N] scripts/run-local.sh <parties> <size> <topology> [PartyMain options...]
# Without NET, the parties talk over localhost. With NET, each party runs in its own network namespace on the
# emulated network, see scripts/net.sh.
# Party logs go to $LOG_DIR (default target/logs). Each party is killed after $TIMEOUT seconds (default 900).
# Each JVM's heap is capped at $HEAP (default 4g), and all of them together at $MEMORY_MAX (default 40G).
# mpc4j's native library is loaded from $MPC4J_NATIVE (default ~/dev/mpc4j/mpc4j-native-tool/cmake-build-release).
# Each JVM sizes its runtime threads (GC, ForkJoin, Netty event loops) for one CPU and uses the Serial GC, while the JIT
# keeps the compiler threads it would have on the whole machine; nothing is pinned. A full collection shrinks the heap
# to what it holds at once, so that the collection before each run returns the memory of the last one. Extra JVM
# flags can be passed in $JAVA_OPTS, and override these. Exits non-zero if any party fails.
set -euo pipefail

if [[ -z ${PCWS_SCOPED:-} ]]; then
  PCWS_SCOPED=1 exec systemd-run --user --scope -q -p MemoryMax="${MEMORY_MAX:-40G}" -p MemorySwapMax=0 \
    "$0" "$@"
fi
launch() { "${@:2}"; }
if [[ -n ${NET:-} ]]; then
  source "$(dirname "$0")/net.sh"
  net_enter "$@"
  launch() { net_in "$@"; }
fi
cd "$(dirname "$0")/.."

n=$1 m=$2 topology=$3
shift 3
log_dir=${LOG_DIR:-target/logs}
mkdir -p "$log_dir"
cp="target/classes:$(cat target/classpath.txt)"
native=${MPC4J_NATIVE:-$HOME/dev/mpc4j/mpc4j-native-tool/cmake-build-release}
jit=$(java -XX:+PrintFlagsFinal -version 2> /dev/null | awk '$2 == "CICompilerCount" { print $4 }')

if [[ -n ${NET:-} ]]; then
  net_setup "$NET" "$n"
  set -- --hosts "$NET_HOSTS" "$@"
fi

pids=()
for ((i = 1; i <= n; i++)); do
  # shellcheck disable=SC2086
  launch "$i" timeout "${TIMEOUT:-900}" java --add-modules jdk.incubator.vector \
    -Xmx"${HEAP:-4g}" -XX:ActiveProcessorCount=1 -XX:+UseSerialGC -XX:-ShrinkHeapInSteps -XX:CICompilerCount="$jit" \
    -Djava.library.path="$native" ${JAVA_OPTS:-} -cp "$cp" \
    anonymous.research.pcws.PartyMain --party "$i" --parties "$n" --size "$m" --topology "$topology" "$@" \
    > "$log_dir/P$i.log" 2>&1 &
  pids+=("$!")
done

status=0
for i in "${!pids[@]}"; do
  if ! wait "${pids[$i]}"; then
    echo "P$((i + 1)) failed, see $log_dir/P$((i + 1)).log" >&2
    status=1
  fi
done
exit "$status"
