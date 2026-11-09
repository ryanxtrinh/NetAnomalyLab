# netanomaly: Network Traffic Anomaly Detection in Java

[![CI](https://github.com/ryanxtrinh/net-anomaly-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanxtrinh/net-anomaly-lab/actions/workflows/ci.yml)

A command-line tool that reads **Zeek** network logs and flags suspicious behavior using five rule-based detectors and an **Isolation Forest** machine-learning model I implemented from scratch. Results are saved as a CSV and as a self-contained HTML report.

Pure Java 17+. No runtime dependencies (JUnit 5 is used for tests only).

## What it detects

| Detector | What it looks for | Why it matters |
|---|---|---|
| `PORT_SCAN` | One source probing many ports on one host, or one port across many hosts, inside a 60s window | Reconnaissance before an attack |
| `BEACONING` | Connections to the same outside server at very regular intervals (low coefficient of variation) | Malware checking in with a C2 server |
| `DNS_TUNNELING` | Long, high-entropy subdomains under one domain | Data being smuggled out through DNS |
| `EXFILTRATION` / `UPLOAD_SPIKE` | Large upload-heavy transfers to one external IP, or uploads far above baseline | Possible data theft |
| `NEW_DEVICE` / `NEW_SERVICE` | Internal IPs or open ports that weren't in the baseline | Rogue devices, unexpected services |
| `ML_ANOMALY` | Statistically unusual connections (Isolation Forest, 10 features) | Catches weird traffic that no rule describes |

## Build

```bash
./build.sh            # needs only a JDK 17+
# or
mvn package           # produces target/netanomaly.jar
```

## Test

```bash
mvn test
```

45 JUnit 5 tests cover each detector with synthetic traffic: a real attack pattern that must
be flagged, plus look-alike normal traffic that must not be (slow scans, jittery browsing,
reverse DNS lookups, LAN file copies). They also cover the Isolation Forest, the Zeek TSV/gzip
parser and the config loader. GitHub Actions runs them on Java 17 and 21 for every push.

## Run

```bash
java -jar netanomaly.jar <zeek_log_dir> [--baseline <zeek_log_dir>] [--out out] [--config my.properties]
```

- `<zeek_log_dir>` must contain `conn.log` (required) and `dns.log` (optional). `.log.gz` files also work.
- `--baseline` points to logs of known-normal traffic. It turns on new-device and upload-spike detection and trains the ML model on clean data.
- Open `out/report.html` in any browser.

## Getting data

### Option A: public datasets
These include real attack traffic with labels, so you can measure how well each detector performs:
- **CIC-IDS2017** (Canadian Institute for Cybersecurity): one PCAP per day, each with known attacks
- **UNSW-NB15**
- **malware-traffic-analysis.net**: real malware infection PCAPs with write-ups

Convert any PCAP to Zeek logs:
```bash
mkdir logs && cd logs
zeek -C -r ../capture.pcap      # -C ignores checksum errors common in captures
cd .. && java -jar netanomaly.jar logs
```

### Option B: your own lab
1. Use a spare Ubuntu machine or VM as the **sensor**. `sudo apt install zeek` (or use the Zeek OBS repo).
2. Capture normal traffic for a few days, then convert it. That's your **baseline**:
   `sudo tcpdump -i eth0 -w baseline.pcap`
3. Capture again later and compare: `java -jar netanomaly.jar logs/ --baseline baseline_logs/`
4. Only capture networks you own or have permission to monitor.

## Tuning

Every threshold is in `config.example.properties`. Tuning is part of the project. Write down:
- which alerts were **false positives** (cloud photo backups often trigger `EXFILTRATION`, and smart TVs often trigger `BEACONING`)
- what you changed and why
- detection rate on the labeled datasets, per detector

## How the code is organized

```
src/main/java/netanomaly/
  Main.java              CLI entry point
  Config.java            thresholds + .properties loader
  io/ZeekReader.java     Zeek TSV parser (reads the #fields header)
  model/                 Conn, DnsQuery, Alert records
  detect/                one class per detector
  ml/IsolationForest.java  from-scratch implementation
  report/ReportWriter.java CSV + HTML report
  util/Net.java          IP classification, entropy, stats helpers
src/test/java/netanomaly/  JUnit 5 tests, mirroring the layout above
```

## Key concepts

- **Zeek `conn_state`**: `SF` = normal completed connection, `S0` = SYN sent with no reply, `REJ` = rejected (RST). Scans produce lots of `S0` and `REJ`.
- **Coefficient of variation (CV)** = std / mean of the gaps between connections. Humans are irregular (high CV), while a `sleep(60)` loop is regular (CV near 0). The beacon detector also uses median absolute deviation so one missed check-in doesn't hide a beacon.
- **Shannon entropy** measures randomness per character. English subdomains score about 2.5–3.5 bits, while encoded data scores about 4 or more.
- **Isolation Forest**: random trees isolate outliers in fewer splits. Score = 2^(−avg path length / c(n)). Near 1 is anomalous, about 0.5 is normal.
