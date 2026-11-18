# PC-WSI

Java implementation of **Private Computation on Weighted Set Intersection (PC-WSI)** built on [mpc4j](https://github.com/alibaba-edu/mpc4j) (v1.1.5):

- **Multi-party reductions** (`STAR`, `RING`, `TREE`): linear OKVS reductions from $n$ parties to 2 parties.
- **Two-party protocols**:
  - `LOOKUP`: server-free two-party PC-WSI based on cuckoo hashing, multi-point OPRF, $\mathbb{Z}_p$ permute-and-share, and anonymous offset lookup.
  - `AIDED`: server-aided two-party PC-WSI ($P_1$, $P_2$, and helper server $P_3$).

## Prerequisites & Build

Requires **OpenJDK 25** and **Maven** on Linux.

1. **Build `mpc4j` v1.1.5** (assumed under `~/dev/mpc4j`):
   - Apply the lazy modular reduction patch for $\mathbb{Z}_p$ OKVS inner products:
     ```bash
     git -C ~/dev/mpc4j apply /path/to/pcwsi/patches/mpc4j-zp-lazy-reduction.patch
     ```
   - Install the required `mpc4j` Java modules under JDK 25:
     ```bash
     mvn -f ~/dev/mpc4j/pom.xml install -DskipTests \
       -Dmaven.compiler.source=25 -Dmaven.compiler.target=25 \
       -pl mpc4j-s2pc-opf -am
     ```
   - Build `mpc4j-native-fourq` and `mpc4j-native-tool` (`libmpc4j-native-tool.so`, default build directory `~/dev/mpc4j/mpc4j-native-tool/cmake-build-release`).

2. **Build `pcwsi` and run unit tests**:
   ```bash
   mvn package
   ```
   If `libmpc4j-native-tool.so` is in a custom directory, pass `-Dmpc4j.native.dir=/path/to/native/dir` to `mvn` and export `MPC4J_NATIVE=/path/to/native/dir` when running scripts.

## Running

`scripts/run-local.sh` launches each party in its own JVM process (logs written to `target/logs/P*.log`; set `PCWS_SCOPED=1` in environments without `systemd --user`, such as containers):

```bash
# Multi-party reduction (STAR | RING | TREE) followed by AIDED (default) or LOOKUP
scripts/run-local.sh 7 4096 TREE --check
scripts/run-local.sh 7 4096 STAR --result LOOKUP --check

# Reduction only (no final two-party protocol)
scripts/run-local.sh 7 4096 RING --result NONE

# Standalone two-party protocols
scripts/run-local.sh 2 4096 LOOKUP --check
scripts/run-local.sh 3 4096 AIDED --check
```

### Emulated Networks & Benchmarks

Set `NET=LAN|WAN-L|WAN-N` to run each party inside its own rootless Linux network namespace (`unshare` + `tc` HTB/netem, 100 Mbit/s and 80 ms RTT for WAN):

```bash
NET=WAN-L scripts/run-local.sh 2 4096 LOOKUP --check
```

To run the full benchmark campaign (including two-step `--record` / `--replay` reduction measurements) and format the resulting CSVs (`data/multi.csv`, `data/two.csv`) as Markdown tables:

```bash
scripts/campaign.sh LAN WAN
scripts/report.py data
```

See the Javadoc of `anonymous.research.pcws.PartyMain` and header comments in `scripts/` for all CLI options and environment variables.
