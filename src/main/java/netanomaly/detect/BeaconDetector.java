package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.Conn;
import netanomaly.util.Net;

import java.util.*;

/**
 * Detects beaconing - malware "checking in" with its command-and-control (C2) server.
 *
 * Humans are irregular: you open a site, read for 3 minutes, click again after 40s.
 * Malware is a loop with a sleep(), so it connects at nearly fixed intervals and
 * usually sends nearly the same number of bytes each time.
 *
 * For each (source, destination, port) pair we measure the gaps between connections:
 *   coefficient of variation (CV) = std(gaps) / mean(gaps)
 * CV near 0 means machine-like regularity. Payload-size consistency is scored the same way.
 */
public class BeaconDetector {

    private final Config cfg;
    public BeaconDetector(Config cfg) { this.cfg = cfg; }

    public List<Alert> run(List<Conn> conns) {
        Map<String, List<Conn>> groups = new HashMap<>();
        for (Conn c : conns) {
            if (cfg.beaconExternalOnly && Net.isInternal(c.dstIp())) continue;
            groups.computeIfAbsent(c.srcIp() + "|" + c.dstIp() + "|" + c.dstPort(), k -> new ArrayList<>()).add(c);
        }

        List<Alert> alerts = new ArrayList<>();
        for (var e : groups.entrySet()) {
            List<Conn> list = e.getValue();
            if (list.size() < cfg.beaconMinConns) continue;
            list.sort(Comparator.comparingDouble(Conn::ts));

            double[] gaps = new double[list.size() - 1];
            for (int i = 1; i < list.size(); i++) gaps[i - 1] = list.get(i).ts() - list.get(i - 1).ts();
            double meanGap = Net.mean(gaps);
            if (meanGap < cfg.beaconMinIntervalSec) continue;

            // Use median absolute deviation so one missed check-in doesn't hide a beacon
            double med = Net.median(gaps);
            double[] dev = new double[gaps.length];
            for (int i = 0; i < gaps.length; i++) dev[i] = Math.abs(gaps[i] - med);
            double robustCv = (1.4826 * Net.median(dev)) / med;
            double cv = Math.min(Net.std(gaps) / meanGap, robustCv);
            if (cv > cfg.beaconMaxCv) continue;

            double[] sizes = list.stream().mapToDouble(Conn::origBytes).toArray();
            double sizeMean = Net.mean(sizes);
            double sizeCv = sizeMean == 0 ? 0 : Net.std(sizes) / sizeMean;

            // Score 0-1: timing regularity weighted most, size consistency second
            double score = 0.7 * (1 - cv / cfg.beaconMaxCv) + 0.3 * Math.max(0, 1 - sizeCv);
            Severity sev = score > 0.8 && list.size() >= 30 ? Severity.HIGH
                         : score > 0.5 ? Severity.MEDIUM : Severity.LOW;

            String[] k = e.getKey().split("\\|");
            alerts.add(new Alert("BEACONING", sev, k[0], k[1] + ":" + k[2],
                    list.get(0).ts(), list.get(list.size() - 1).ts(), round(score),
                    String.format("%d connections every ~%.1fs (interval CV %.3f), avg upload %s (size CV %.2f)",
                            list.size(), med, cv, Net.bytes((long) sizeMean), sizeCv)));
        }
        return alerts;
    }

    private static double round(double v) { return Math.round(v * 1000) / 1000.0; }
}
