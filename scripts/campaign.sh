#!/usr/bin/env bash
# Runs the paper's measurements, one phase per argument, and appends the CSV rows under $OUT (default data):
#   LAN: the reductions alone for every topology, n in {3, 4, 7, 15} and m in {2^12, 2^16, 2^20}, then the two-party
#        protocols LOOKUP, AIDED and PFA-WSI for every m;
#   WAN: on each network in $WANS (default "WAN-L WAN-N"), the reductions alone at n in {7, 15} and m = 2^20, then
#        the two-party protocols. LOOKUP and PFA-WSI run on WAN-L only, which equals WAN-N for two parties.
# Usage: scripts/campaign.sh <LAN|WAN>...
# A reduction runs in two steps, see Schedule.java: it is recorded once on localhost with the parties computing one at
# a time (rows labelled record, times in $OUT/times), then replayed on each network (rows labelled with the network).
# $SIZES (default "4096 65536 1048576") lists m, and the WAN reductions use the last one. Each configuration runs
# $REPS times (default 3). PFA=1 also runs the PFA-WSI baseline (default 0). Party logs go to $OUT/logs, one directory per configuration, and
# progress to $OUT/campaign.log. A failed configuration is logged and skipped.
# PFA-WSI (IMWS) runs from the image localhost/pfa-wsi-net, see scripts/pfa-wsi-net.Containerfile, with both parties
# in one container and its rows in $OUT/pfa-<LAN|WAN>/benchmark_results.csv. Its WAN shapes the container's loopback
# like WAN-L in scripts/net.sh: packets from the server's listening ports form one direction, all others the other.
# After each WAN run, the byte counters of both directions go to its log.
set -euo pipefail
cd "$(dirname "$0")/.."

out=${OUT:-data}
reps=${REPS:-3}
export RATE=${RATE:-100mbit} DELAY=${DELAY:-40ms}
rate=$RATE delay=$DELAY
read -ra sizes <<< "${SIZES:-4096 65536 1048576}"
read -ra wans <<< "${WANS:-WAN-L WAN-N}"
mkdir -p "$out/logs"

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$out/campaign.log"
}

# pcws <network|record> <csv> <heap> <parties> <size> <topology> [PartyMain options...]
# record runs on localhost.
pcws() {
  local label=$1 net=$1 csv=$2 heap=$3 tag="$1-$4-$5-$6"
  [[ $net == record ]] && net=
  shift 3
  log "start $tag"
  if NET=$net HEAP=$heap LOG_DIR="$out/logs/$tag" scripts/run-local.sh "$@" --reps "$reps" --label "$label" \
    --csv "$out/$csv"; then
    log "done $tag"
  else
    log "FAILED $tag"
  fi
}

# reduction <network> <parties> <size> <topology>: records the reduction unless all runs are recorded already, then
# replays it on the network
reduction() {
  local net=$1 n=$2 m=$3 t=$4 times="$out/times/$4-$2-$3"
  if [[ $(cat "$times/P1.txt" 2> /dev/null | wc -l) -lt $reps ]]; then
    pcws record multi.csv 4g "$n" "$m" "$t" --result NONE --record "$times"
  fi
  pcws "$net" multi.csv 4g "$n" "$m" "$t" --result NONE --replay "$times"
}

# pfa <LAN|WAN> <size>
pfa() {
  local net=$1 m=$2 tag="pfa-$1-$2" shape=: stats=: r p
  [[ ${PFA:-0} == 0 ]] && return
  mkdir -p "$out/pfa-$net"
  if [[ $net == WAN ]]; then
    stats="tc -s class show dev lo"
    shape="ip link set lo mtu 1500
      tc qdisc add dev lo root handle 1: htb r2q 1000 default 2
      for c in 1 2; do
        tc class add dev lo parent 1: classid 1:\$c htb rate $rate
        tc qdisc add dev lo parent 1:\$c netem delay $delay
      done"
    for p in 7700 7708 7711; do
      shape+="
      tc filter add dev lo parent 1: protocol ip u32 match ip sport $p 0xffff flowid 1:1"
    done
  fi
  for ((r = 1; r <= reps; r++)); do
    log "start $tag run $r"
    if podman run --rm --pull never --network none --cap-add NET_ADMIN --memory 40g --memory-swap 40g \
      -v "$(realpath "$out/pfa-$net"):/work:Z" --entrypoint /bin/bash localhost/pfa-wsi-net \
      -c "set -e; $shape; pfa-wsi IMWS $m $m; $stats" >> "$out/logs/$tag.log" 2>&1; then
      log "done $tag run $r"
    else
      log "FAILED $tag run $r"
    fi
  done
}

lan() {
  local m n t
  for m in "${sizes[@]}"; do
    for n in 3 4 7 15; do
      for t in STAR RING TREE; do
        reduction LAN "$n" "$m" "$t"
      done
    done
  done
  for m in "${sizes[@]}"; do
    pcws LAN two.csv 6g 2 "$m" LOOKUP --check
    pcws LAN two.csv 4g 3 "$m" AIDED --check
    pfa LAN "$m"
  done
}

wan() {
  local m n net t
  for net in "${wans[@]}"; do
    for n in 7 15; do
      for t in STAR RING TREE; do
        reduction "$net" "$n" "${sizes[-1]}" "$t"
      done
    done
    for m in "${sizes[@]}"; do
      pcws "$net" two.csv 4g 3 "$m" AIDED --check
      # With two parties, each node has a single link, so WAN-N equals WAN-L
      if [[ $net == WAN-L ]]; then
        pcws WAN-L two.csv 6g 2 "$m" LOOKUP --check
        pfa WAN "$m"
      fi
    done
  done
}

log "phases $* with REPS=$reps RATE=$rate DELAY=$delay WANS=${wans[*]} PFA=${PFA:-0}"
for phase in "$@"; do
  case $phase in
    LAN) lan ;;
    WAN) wan ;;
    *) echo "unknown phase $phase, expected LAN or WAN" >&2; exit 1 ;;
  esac
done
log "finished"
