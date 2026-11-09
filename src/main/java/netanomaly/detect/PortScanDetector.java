package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.Conn;

import java.util.*;

/**
 * Detects port scans.
 *
 *  - Vertical scan:   one source hits many different PORTS on one host  (nmap 192.168.1.15)
 *  - Horizontal sweep: one source hits the same port on many HOSTS     (nmap -p22 192.168.1.0/24)
 *
 * Traffic is cut into fixed time windows (default 60s). A real user almost never
 * touches 25+ ports on one machine within a minute; a scanner does it in seconds.
 * Most probes fail (S0 = no reply, REJ = rejected), so the failure rate is reported too.
 */
public class PortScanDetector {

    private final Config cfg;
    public PortScanDetector(Config cfg) { this.cfg = cfg; }

    private static final class Agg {
        Set<Integer> ports = new HashSet<>();
        Set<String> hosts = new HashSet<>();
        int total, failed;
        double first = Double.MAX_VALUE, last = 0;
        void add(Conn c) {
            total++; if (c.failed()) failed++;
            first = Math.min(first, c.ts()); last = Math.max(last, c.ts());
        }
    }

    public List<Alert> run(List<Conn> conns) {
        // key -> window -> aggregate
        Map<String, Map<Long, Agg>> vertical = new HashMap<>();   // src|dst -> ports
        Map<String, Map<Long, Agg>> horizontal = new HashMap<>(); // src|port -> hosts

        for (Conn c : conns) {
            if (c.proto().equals("icmp")) continue;
            long w = (long) Math.floor(c.ts() / cfg.scanWindowSec);
            Agg v = vertical.computeIfAbsent(c.srcIp() + "|" + c.dstIp(), k -> new HashMap<>())
                    .computeIfAbsent(w, k -> new Agg());
            v.ports.add(c.dstPort()); v.add(c);
            Agg h = horizontal.computeIfAbsent(c.srcIp() + "|" + c.dstPort() + "/" + c.proto(), k -> new HashMap<>())
                    .computeIfAbsent(w, k -> new Agg());
            h.hosts.add(c.dstIp()); h.add(c);
        }

        List<Alert> alerts = new ArrayList<>();

        for (var e : vertical.entrySet()) {
            Agg merged = mergeFlagged(e.getValue(), true);
            if (merged == null) continue;
            String[] k = e.getKey().split("\\|");
            int n = merged.ports.size();
            double failPct = 100.0 * merged.failed / merged.total;
            Severity sev = n >= 200 ? Severity.HIGH : n >= 60 ? Severity.MEDIUM : Severity.LOW;
            alerts.add(new Alert("PORT_SCAN", sev, k[0], k[1], merged.first, merged.last, n,
                    String.format("Vertical scan: %d distinct ports probed in %.0fs, %.0f%% of %d attempts failed (%s)",
                            n, merged.last - merged.first, failPct, merged.total, samplePorts(merged.ports))));
        }

        for (var e : horizontal.entrySet()) {
            Agg merged = mergeFlagged(e.getValue(), false);
            if (merged == null) continue;
            String[] k = e.getKey().split("\\|");
            int n = merged.hosts.size();
            Severity sev = n >= 100 ? Severity.HIGH : n >= 40 ? Severity.MEDIUM : Severity.LOW;
            alerts.add(new Alert("PORT_SCAN", sev, k[0], "port " + k[1], merged.first, merged.last, n,
                    String.format("Horizontal sweep: %d different hosts contacted on port %s in %.0fs, %.0f%% failed",
                            n, k[1], merged.last - merged.first, 100.0 * merged.failed / merged.total)));
        }
        return alerts;
    }

    /** Combine every window that crossed the threshold into one alert, so a 3-minute scan = 1 alert. */
    private Agg mergeFlagged(Map<Long, Agg> windows, boolean vertical) {
        Agg out = null;
        for (Agg a : windows.values()) {
            boolean hit = vertical ? a.ports.size() >= cfg.scanPortThreshold
                                   : a.hosts.size() >= cfg.scanHostThreshold;
            if (!hit) continue;
            if (out == null) out = new Agg();
            out.ports.addAll(a.ports); out.hosts.addAll(a.hosts);
            out.total += a.total; out.failed += a.failed;
            out.first = Math.min(out.first, a.first); out.last = Math.max(out.last, a.last);
        }
        return out;
    }

    private static String samplePorts(Set<Integer> ports) {
        List<Integer> s = new ArrayList<>(ports); Collections.sort(s);
        return "ports " + s.get(0) + "-" + s.get(s.size() - 1);
    }
}
