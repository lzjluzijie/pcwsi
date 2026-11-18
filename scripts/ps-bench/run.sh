#!/usr/bin/env bash
# Benchmarks PermuteShare alone: a sender and a receiver JVM on localhost, one CSV row per phase and repetition.
# Usage: scripts/ps-bench/run.sh <m> <silent true|false> <reps> [check]
# Output goes to $OUT-{0,1}.log (default target/ps-bench/m<m>-<cot>) with peak RSS in $OUT-{0,1}.time.
# Each JVM's heap is capped at $HEAP (default 4g), and its runtime threads and GC are set up as in run-local.sh.
# JFR=1 also records $OUT-{0,1}.jfr.
# mpc4j's native library is loaded from $MPC4J_NATIVE (default ~/dev/mpc4j/mpc4j-native-tool/cmake-build-release).
set -euo pipefail
here=$(dirname "$(readlink -f "$0")")
cd "$here/../.."

m=$1 silent=$2 reps=$3
cp="target/classes:$(cat target/classpath.txt)"
native=${MPC4J_NATIVE:-$HOME/dev/mpc4j/mpc4j-native-tool/cmake-build-release}
out=${OUT:-target/ps-bench/m$m-$([[ $silent == true ]] && echo silent || echo iknp)}
jit=$(java -XX:+PrintFlagsFinal -version 2> /dev/null | awk '$2 == "CICompilerCount" { print $4 }')
mkdir -p "$(dirname "$out")"

pids=()
for role in 0 1; do
  jfr=()
  if [[ ${JFR:-0} == 1 ]]; then
    jfr=(-XX:StartFlightRecording=filename="$out-$role.jfr",settings=profile)
  fi
  /usr/bin/time -f "maxrss_kb=%M" -o "$out-$role.time" \
    timeout "${TIMEOUT:-1800}" java --add-modules jdk.incubator.vector -Xmx"${HEAP:-4g}" -XX:ActiveProcessorCount=1 \
    -XX:+UseSerialGC -XX:-ShrinkHeapInSteps -XX:CICompilerCount="$jit" -Djava.library.path="$native" "${jfr[@]}" \
    -cp "$cp" "$here/PsBench.java" "$role" "$m" "$silent" 8900 "$reps" ${4:-} > "$out-$role.log" 2>&1 &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
grep -h -E '^(sender|receiver),' "$out-0.log" "$out-1.log" || true
cat "$out-0.time" "$out-1.time"
exit "$status"
