package netanomaly.detect;

import netanomaly.Config;
import netanomaly.ml.IsolationForest;
import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.Conn;
import netanomaly.util.Net;

import java.util.*;

/**
 * Unsupervised anomaly detection with an Isolation Forest.
 *
 * Unlike the rule-based detectors, this one has no idea what an "attack" is - it
 * only learns what typical connections look like and reports the oddest ones.
 * If a baseline is given, the model trains on the baseline (clean traffic) and
 * scores the new capture. Otherwise it trains and scores on the same data.
 *
 * Comparing what the ML catches vs. what the rules catch is a good section for your report.
 */
public class MlDetector {

    private final Config cfg;
    public MlDetector(Config cfg) { this.cfg = cfg; }

    public static final String[] FEATURES = {
            "log_duration", "log_orig_bytes", "log_resp_bytes", "log_orig_pkts", "log_resp_pkts",
            "log_dst_port", "is_udp", "failed", "dst_external", "upload_ratio"
    };

    static double[] features(Conn c) {
        double ratio = Math.log1p(c.origBytes()) - Math.log1p(c.respBytes());
        return new double[]{
                Math.log1p(c.duration()),
                Math.log1p(c.origBytes()),
                Math.log1p(c.respBytes()),
                Math.log1p(c.origPkts()),
                Math.log1p(c.respPkts()),
                Math.log1p(c.dstPort()),
                c.proto().equals("udp") ? 1 : 0,
                c.failed() ? 1 : 0,
                Net.isInternal(c.dstIp()) ? 0 : 1,
                ratio
        };
    }

    public List<Alert> run(List<Conn> conns, List<Conn> baseline) {
        if (conns.size() < 50) return List.of();
        List<Conn> train = (baseline != null && baseline.size() >= 50) ? baseline : conns;

        double[][] trainX = train.stream().map(MlDetector::features).toArray(double[][]::new);
        IsolationForest forest = new IsolationForest(cfg.mlTrees, cfg.mlSampleSize, cfg.mlSeed);
        forest.fit(trainX);

        // Score every connection, then group by src -> dst:port so one noisy pair = one alert
        Map<String, double[]> groups = new HashMap<>(); // key -> [maxScore, count, first, last]
        for (Conn c : conns) {
            double s = forest.score(features(c));
            if (s < cfg.mlScoreThreshold) continue;
            String key = c.srcIp() + "|" + c.dstIp() + ":" + c.dstPort() + "/" + c.proto();
            double[] g = groups.computeIfAbsent(key, k -> new double[]{0, 0, Double.MAX_VALUE, 0});
            g[0] = Math.max(g[0], s); g[1]++; g[2] = Math.min(g[2], c.ts()); g[3] = Math.max(g[3], c.ts());
        }

        List<Alert> alerts = new ArrayList<>();
        groups.entrySet().stream()
                .sorted((a, b) -> Double.compare(b.getValue()[0], a.getValue()[0]))
                .limit(cfg.mlMaxAlerts)
                .forEach(e -> {
                    double[] g = e.getValue();
                    String[] k = e.getKey().split("\\|");
                    Severity sev = g[0] >= 0.72 ? Severity.MEDIUM : Severity.LOW;
                    alerts.add(new Alert("ML_ANOMALY", sev, k[0], k[1], g[2], g[3], Math.round(g[0] * 1000) / 1000.0,
                            String.format("Isolation Forest score %.3f on %d unusual connection(s) (trained on %s)",
                                    g[0], (int) g[1], train == conns ? "same capture" : "baseline")));
                });
        return alerts;
    }
}
