package netanomaly;

import netanomaly.detect.*;
import netanomaly.io.ZeekReader;
import netanomaly.model.Alert;
import netanomaly.model.Conn;
import netanomaly.model.DnsQuery;
import netanomaly.report.ReportWriter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * netanomaly - find anomalies in Zeek network logs.
 *
 * Usage:
 *   java -jar netanomaly.jar <zeek_log_dir> [--baseline <zeek_log_dir>] [--out <dir>] [--config <file>]
 */
public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) { usage(); return; }

        Path logs = Path.of(args[0]);
        Path baselineDir = null, out = Path.of("out"), cfgFile = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--baseline" -> baselineDir = Path.of(args[++i]);
                case "--out" -> out = Path.of(args[++i]);
                case "--config" -> cfgFile = Path.of(args[++i]);
                default -> { System.err.println("Unknown option: " + args[i]); usage(); System.exit(2); }
            }
        }
        Config cfg = Config.load(cfgFile);

        System.out.println("Reading Zeek logs from " + logs);
        List<Conn> conns = ZeekReader.readConn(find(logs, "conn"));
        Path dnsFile = findOptional(logs, "dns");
        List<DnsQuery> dns = dnsFile == null ? List.of() : ZeekReader.readDns(dnsFile);
        System.out.printf("  %,d connections, %,d DNS queries%n", conns.size(), dns.size());

        List<Conn> baseline = null;
        if (baselineDir != null) {
            baseline = ZeekReader.readConn(find(baselineDir, "conn"));
            System.out.printf("  baseline: %,d connections%n", baseline.size());
        }

        List<Alert> alerts = new ArrayList<>();
        run("Port scans", alerts, new PortScanDetector(cfg).run(conns));
        run("Beaconing", alerts, new BeaconDetector(cfg).run(conns));
        run("DNS tunneling", alerts, new DnsTunnelDetector(cfg).run(dns));
        run("Exfiltration", alerts, new ExfilDetector(cfg).run(conns, baseline));
        run("New devices/services", alerts, new NewDeviceDetector().run(conns, baseline));
        run("Isolation Forest", alerts, new MlDetector(cfg).run(conns, baseline));

        alerts.sort(Comparator.comparing((Alert a) -> a.severity()).reversed()
                .thenComparing(Alert::detector).thenComparingDouble(Alert::firstSeen));

        Files.createDirectories(out);
        ReportWriter.writeCsv(alerts, out.resolve("alerts.csv"));
        ReportWriter.writeHtml(alerts, conns, dns, logs.toString(), out.resolve("report.html"));

        System.out.printf("%nDone: %d alerts%n  %s%n  %s%n", alerts.size(),
                out.resolve("alerts.csv"), out.resolve("report.html"));
    }

    private static void run(String name, List<Alert> all, List<Alert> found) {
        System.out.printf("  %-22s %d alert(s)%n", name, found.size());
        all.addAll(found);
    }

    private static Path find(Path dir, String name) throws java.io.IOException {
        Path p = findOptional(dir, name);
        if (p == null) throw new java.io.IOException("No " + name + ".log found in " + dir);
        return p;
    }

    private static Path findOptional(Path dir, String name) {
        if (Files.isRegularFile(dir)) return dir.getFileName().toString().startsWith(name) ? dir : null;
        for (String f : new String[]{name + ".log", name + ".log.gz"}) {
            Path p = dir.resolve(f);
            if (Files.exists(p)) return p;
        }
        return null;
    }

    private static void usage() {
        System.out.println("""
                netanomaly - find anomalies in Zeek network logs

                Usage:
                  java -jar netanomaly.jar <zeek_log_dir> [options]

                Options:
                  --baseline <dir>   Zeek logs of known-normal traffic (enables NEW_DEVICE,
                                     NEW_SERVICE, UPLOAD_SPIKE, and trains the ML model on it)
                  --out <dir>        Where to write alerts.csv and report.html (default: out)
                  --config <file>    Override detection thresholds (see config.example.properties)
                """);
    }
}
