package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.Conn;
import netanomaly.util.Net;

import java.util.*;

/**
 * Detects possible data exfiltration: an internal machine uploading far more
 * than it downloads to a single outside address.
 *
 * Most home traffic is download-heavy (web pages, video). A large, upload-heavy
 * transfer to an unfamiliar external IP is worth a look - though cloud backups
 * (Google Photos, iCloud, OneDrive) can trigger this legitimately. Investigating
 * and explaining those false positives is a great thing to put in your write-up.
 *
 * If a baseline is supplied, a host is also flagged when its total upload is far
 * above anything it did during the baseline period.
 */
public class ExfilDetector {

    private final Config cfg;
    public ExfilDetector(Config cfg) { this.cfg = cfg; }

    private static final class Agg {
        long up, down; int conns; double first = Double.MAX_VALUE, last;
    }

    public List<Alert> run(List<Conn> conns, List<Conn> baseline) {
        Map<String, Agg> pairs = aggregate(conns);
        List<Alert> alerts = new ArrayList<>();

        for (var e : pairs.entrySet()) {
            Agg a = e.getValue();
            if (a.up < cfg.exfilMinBytes) continue;
            double ratio = a.up / (double) Math.max(1, a.down);
            if (ratio < cfg.exfilUploadRatio) continue;
            String[] k = e.getKey().split("\\|");
            Severity sev = a.up >= 1024L * 1024 * 1024 ? Severity.HIGH
                         : a.up >= 3 * cfg.exfilMinBytes ? Severity.MEDIUM : Severity.LOW;
            alerts.add(new Alert("EXFILTRATION", sev, k[0], k[1], a.first, a.last, a.up,
                    String.format("Uploaded %s vs downloaded %s (%.0fx) over %d connections",
                            Net.bytes(a.up), Net.bytes(a.down), ratio, a.conns)));
        }

        if (baseline != null && !baseline.isEmpty()) {
            Map<String, Long> baseUp = perHostUpload(baseline);
            double baseHours = Math.max(1, span(baseline) / 3600.0);
            double testHours = Math.max(1, span(conns) / 3600.0);
            for (var e : perHostUpload(conns).entrySet()) {
                long before = baseUp.getOrDefault(e.getKey(), 0L);
                double beforeRate = before / baseHours, nowRate = e.getValue() / testHours;
                if (nowRate > 10 * Math.max(beforeRate, 1024 * 1024) && e.getValue() >= cfg.exfilMinBytes) {
                    alerts.add(new Alert("UPLOAD_SPIKE", Severity.MEDIUM, e.getKey(), "(all external)",
                            0, 0, nowRate / Math.max(beforeRate, 1),
                            String.format("Uploading %s/hour vs %s/hour during baseline",
                                    Net.bytes((long) nowRate), Net.bytes((long) beforeRate))));
                }
            }
        }
        return alerts;
    }

    private Map<String, Agg> aggregate(List<Conn> conns) {
        Map<String, Agg> m = new HashMap<>();
        for (Conn c : conns) {
            if (!Net.isInternal(c.srcIp()) || Net.isInternal(c.dstIp())) continue;
            Agg a = m.computeIfAbsent(c.srcIp() + "|" + c.dstIp(), k -> new Agg());
            a.up += c.origBytes(); a.down += c.respBytes(); a.conns++;
            a.first = Math.min(a.first, c.ts()); a.last = Math.max(a.last, c.ts() + c.duration());
        }
        return m;
    }

    private Map<String, Long> perHostUpload(List<Conn> conns) {
        Map<String, Long> m = new HashMap<>();
        for (Conn c : conns)
            if (Net.isInternal(c.srcIp()) && !Net.isInternal(c.dstIp()))
                m.merge(c.srcIp(), c.origBytes(), Long::sum);
        return m;
    }

    private static double span(List<Conn> conns) {
        double lo = Double.MAX_VALUE, hi = 0;
        for (Conn c : conns) { lo = Math.min(lo, c.ts()); hi = Math.max(hi, c.ts()); }
        return hi - lo;
    }
}
