package netanomaly.report;

import netanomaly.model.Alert;
import netanomaly.model.Conn;
import netanomaly.model.DnsQuery;
import netanomaly.util.Net;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Writes alerts.csv and a self-contained report.html (open it in any browser, no server needed). */
public final class ReportWriter {

    private ReportWriter() {}

    public static void writeCsv(List<Alert> alerts, Path file) throws IOException {
        StringBuilder sb = new StringBuilder("detector,severity,src,dst,first_seen,last_seen,score,details\n");
        for (Alert a : alerts) {
            sb.append(String.join(",", a.detector(), a.severity().name(), csv(a.src()), csv(a.dst()),
                    a.firstSeen() > 0 ? Net.time(a.firstSeen()) : "",
                    a.lastSeen() > 0 ? Net.time(a.lastSeen()) : "",
                    String.valueOf(a.score()), csv(a.details()))).append('\n');
        }
        Files.writeString(file, sb.toString());
    }

    private static String csv(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static final Map<String, String> EXPLAIN = new LinkedHashMap<>();
    static {
        EXPLAIN.put("PORT_SCAN", "One source probing many ports or many hosts in a short time - reconnaissance before an attack.");
        EXPLAIN.put("BEACONING", "Connections at machine-regular intervals to the same outside server - typical of malware checking in with C2.");
        EXPLAIN.put("DNS_TUNNELING", "Long, random-looking subdomains under one domain - data being smuggled out through DNS.");
        EXPLAIN.put("EXFILTRATION", "An internal host uploading far more than it downloads to one external address.");
        EXPLAIN.put("UPLOAD_SPIKE", "A host uploading much more per hour than it did during the baseline.");
        EXPLAIN.put("NEW_DEVICE", "An internal IP that never appeared in the baseline capture.");
        EXPLAIN.put("NEW_SERVICE", "An internal host:port that started accepting connections after the baseline.");
        EXPLAIN.put("ML_ANOMALY", "Connections the Isolation Forest found statistically unusual compared to the rest of the traffic.");
    }

    public static void writeHtml(List<Alert> alerts, List<Conn> conns, List<DnsQuery> dns,
                                 String source, Path file) throws IOException {
        Map<String, Integer> byDetector = new TreeMap<>();
        int[] sev = new int[3];
        for (Alert a : alerts) {
            byDetector.merge(a.detector(), 1, Integer::sum);
            sev[a.severity().ordinal()]++;
        }
        Set<String> hosts = new HashSet<>();
        long totalBytes = 0;
        double t0 = Double.MAX_VALUE, t1 = 0;
        for (Conn c : conns) {
            hosts.add(c.srcIp());
            totalBytes += c.origBytes() + c.respBytes();
            t0 = Math.min(t0, c.ts()); t1 = Math.max(t1, c.ts());
        }

        StringBuilder h = new StringBuilder();
        h.append("""
                <!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Network Anomaly Report</title><style>
                :root{--bg:#0f1419;--panel:#171d24;--line:#2a333d;--text:#e6e9ed;--muted:#8b96a3;
                --high:#f0605d;--med:#f2a541;--low:#5aa9e6;--accent:#4fd1a5}
                *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
                font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
                .wrap{max-width:1150px;margin:0 auto;padding:28px 20px}
                h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 12px;color:var(--accent);
                text-transform:uppercase;letter-spacing:.06em}.muted{color:var(--muted)}
                .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
                .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
                .card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:12px}
                .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
                .bar{display:flex;align-items:center;gap:10px;margin:7px 0}.bar .lbl{width:130px;font-size:12px}
                .bar .fill{height:18px;background:var(--accent);border-radius:4px;min-width:3px}
                table{width:100%;border-collapse:collapse;font-size:13px}
                th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
                th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel)}
                .sev{font-weight:700;font-size:11px;padding:2px 7px;border-radius:99px;color:#111}
                .HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}
                .filters button{background:var(--panel);color:var(--text);border:1px solid var(--line);
                border-radius:99px;padding:5px 12px;margin:0 6px 8px 0;cursor:pointer}
                .filters button.on{border-color:var(--accent);color:var(--accent)}
                code{font-family:ui-monospace,Menlo,monospace;font-size:12px}
                dl{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;margin:0}dt{font-weight:600}dd{margin:0;color:var(--muted)}
                .scroll{overflow-x:auto}
                </style></head><body><div class="wrap">
                """);
        h.append("<h1>Network Anomaly Report</h1><div class='muted'>Source: <code>").append(esc(source))
         .append("</code> &middot; ").append(conns.isEmpty() ? "" : Net.time(t0) + " &rarr; " + Net.time(t1)).append("</div>");

        h.append("<div class='cards'>")
         .append(card(String.valueOf(alerts.size()), "Total alerts"))
         .append(card("<span style='color:var(--high);font-size:24px'>" + sev[2] + "</span>", "High"))
         .append(card("<span style='color:var(--med);font-size:24px'>" + sev[1] + "</span>", "Medium"))
         .append(card("<span style='color:var(--low);font-size:24px'>" + sev[0] + "</span>", "Low"))
         .append(card(String.format("%,d", conns.size()), "Connections"))
         .append(card(String.format("%,d", dns.size()), "DNS queries"))
         .append(card(String.valueOf(hosts.size()), "Source hosts"))
         .append(card(Net.bytes(totalBytes), "Total traffic"))
         .append("</div>");

        // Timeline
        h.append("<h2>Traffic timeline</h2><div class='panel'>").append(timeline(conns, alerts, t0, t1))
         .append("<div class='muted' style='font-size:12px'>Connections per bucket. Markers show when alerts began "
                 + "(<span style='color:var(--high)'>&#9650;</span> high, <span style='color:var(--med)'>&#9650;</span> medium).</div></div>");

        // Bar chart
        h.append("<h2>Alerts by detector</h2><div class='panel'>");
        int max = byDetector.values().stream().max(Integer::compare).orElse(1);
        for (var e : byDetector.entrySet()) {
            h.append("<div class='bar'><div class='lbl'>").append(e.getKey()).append("</div><div class='fill' style='width:")
             .append(Math.max(1, 70 * e.getValue() / max)).append("%'></div><div>").append(e.getValue()).append("</div></div>");
        }
        if (byDetector.isEmpty()) h.append("<div class='muted'>No alerts - quiet network (or thresholds too high).</div>");
        h.append("</div>");

        // Table
        h.append("<h2>Alerts</h2><div class='filters'><button class='on' data-f='ALL'>All</button>");
        for (String d : byDetector.keySet()) h.append("<button data-f='").append(d).append("'>").append(d).append("</button>");
        h.append("</div><div class='panel scroll'><table id='t'><thead><tr><th>Severity</th><th>Detector</th><th>Source</th>"
                + "<th>Destination</th><th>First seen</th><th>Details</th></tr></thead><tbody>");
        for (Alert a : alerts) {
            h.append("<tr data-d='").append(a.detector()).append("'><td><span class='sev ").append(a.severity())
             .append("'>").append(a.severity()).append("</span></td><td>").append(a.detector())
             .append("</td><td><code>").append(esc(a.src())).append("</code></td><td><code>").append(esc(a.dst()))
             .append("</code></td><td>").append(a.firstSeen() > 0 ? Net.time(a.firstSeen()) : "-")
             .append("</td><td>").append(esc(a.details())).append("</td></tr>");
        }
        h.append("</tbody></table></div>");

        h.append("<h2>What each detector looks for</h2><div class='panel'><dl>");
        EXPLAIN.forEach((k, v) -> h.append("<dt>").append(k).append("</dt><dd>").append(v).append("</dd>"));
        h.append("</dl></div><p class='muted' style='font-size:12px;margin-top:24px'>Generated by netanomaly. "
                + "Every alert is a lead, not a verdict - confirm in Wireshark before concluding anything.</p>");

        h.append("""
                <script>
                document.querySelectorAll('.filters button').forEach(b=>b.onclick=()=>{
                  document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
                  const f=b.dataset.f;document.querySelectorAll('#t tbody tr').forEach(r=>
                    r.style.display=(f==='ALL'||r.dataset.d===f)?'':'none');});
                </script></div></body></html>
                """);
        Files.writeString(file, h.toString());
    }

    private static String card(String big, String label) {
        return "<div class='card'><b>" + big + "</b><span>" + label + "</span></div>";
    }

    private static String timeline(List<Conn> conns, List<Alert> alerts, double t0, double t1) {
        if (conns.isEmpty() || t1 <= t0) return "<div class='muted'>No data</div>";
        int buckets = 120, W = 1000, H = 180, pad = 30;
        double width = (t1 - t0) / buckets;
        int[] counts = new int[buckets];
        for (Conn c : conns) counts[Math.min(buckets - 1, (int) ((c.ts() - t0) / width))]++;
        int max = Arrays.stream(counts).max().orElse(1);

        StringBuilder s = new StringBuilder("<svg viewBox='0 0 " + W + " " + (H + pad) + "' width='100%' role='img'>");
        s.append("<text x='0' y='12' fill='#8b96a3' font-size='11'>").append(max).append("</text>");
        s.append("<line x1='0' y1='").append(H).append("' x2='").append(W).append("' y2='").append(H).append("' stroke='#2a333d'/>");
        StringBuilder pts = new StringBuilder();
        for (int i = 0; i < buckets; i++) {
            double x = (double) i / (buckets - 1) * W, y = H - (double) counts[i] / max * (H - 20);
            pts.append(String.format(Locale.ROOT, "%.1f,%.1f ", x, y));
        }
        s.append("<polyline fill='none' stroke='#4fd1a5' stroke-width='2' points='").append(pts).append("'/>");
        for (Alert a : alerts) {
            if (a.firstSeen() <= 0 || a.severity() == Alert.Severity.LOW) continue;
            double x = (a.firstSeen() - t0) / (t1 - t0) * W;
            String col = a.severity() == Alert.Severity.HIGH ? "#f0605d" : "#f2a541";
            s.append(String.format(Locale.ROOT, "<path d='M%.1f %d l-6 10 h12z' fill='%s'><title>%s %s</title></path>",
                    x, H + 4, col, a.detector(), esc(a.src())));
        }
        s.append("<text x='0' y='").append(H + pad).append("' fill='#8b96a3' font-size='11'>").append(Net.time(t0)).append("</text>");
        s.append("<text x='").append(W).append("' y='").append(H + pad).append("' text-anchor='end' fill='#8b96a3' font-size='11'>")
         .append(Net.time(t1)).append("</text></svg>");
        return s.toString();
    }
}
