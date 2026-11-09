package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.DnsQuery;
import netanomaly.util.Net;

import java.util.*;

/**
 * Detects DNS tunneling - smuggling data out inside DNS lookups.
 *
 * Normal:     www.google.com, api.spotify.com
 * Tunneling:  mzxw6ytboi4dmnrrgu3tcmzx.gezdgnbvgy3tq.update-check.xyz
 *
 * The attacker encodes stolen data as the subdomain and runs the DNS server
 * for the base domain, so every lookup delivers a chunk. Tell-tale signs:
 * long subdomains, high randomness (entropy), many unique names under one domain,
 * and often TXT record types.
 */
public class DnsTunnelDetector {

    private final Config cfg;
    public DnsTunnelDetector(Config cfg) { this.cfg = cfg; }

    private static final class Agg {
        int total, suspicious, txt;
        Set<String> uniqueSubs = new HashSet<>();
        double maxEntropy, first = Double.MAX_VALUE, last;
        String example = "";
    }

    public List<Alert> run(List<DnsQuery> queries) {
        Map<String, Agg> byClientDomain = new HashMap<>();

        for (DnsQuery q : queries) {
            String name = q.query().toLowerCase(Locale.ROOT);
            if (name.endsWith(".arpa") || name.endsWith(".local")) continue; // reverse lookups / mDNS
            String[] labels = name.split("\\.");
            if (labels.length < 3) continue;

            // Base domain = last two labels. (Simplification: "co.uk"-style suffixes count as one level less.)
            String base = labels[labels.length - 2] + "." + labels[labels.length - 1];
            String sub = name.substring(0, name.length() - base.length() - 1).replace(".", "");

            Agg a = byClientDomain.computeIfAbsent(q.clientIp() + "|" + base, k -> new Agg());
            a.total++;
            a.uniqueSubs.add(sub);
            if (q.qtypeName().equals("TXT")) a.txt++;
            a.first = Math.min(a.first, q.ts()); a.last = Math.max(a.last, q.ts());

            double h = Net.entropy(sub);
            if (sub.length() >= cfg.dnsMinSubdomainLen && h >= cfg.dnsMinEntropy) {
                a.suspicious++;
                if (h > a.maxEntropy) { a.maxEntropy = h; a.example = name; }
            }
        }

        List<Alert> alerts = new ArrayList<>();
        for (var e : byClientDomain.entrySet()) {
            Agg a = e.getValue();
            if (a.suspicious < cfg.dnsMinSuspiciousQueries) continue;
            String[] k = e.getKey().split("\\|");
            double share = (double) a.suspicious / a.total;
            Severity sev = a.suspicious >= 100 ? Severity.HIGH : a.suspicious >= 30 ? Severity.MEDIUM : Severity.LOW;
            alerts.add(new Alert("DNS_TUNNELING", sev, k[0], k[1], a.first, a.last, a.suspicious,
                    String.format("%d long/high-entropy lookups (%.0f%% of %d), %d unique subdomains, %d TXT, max entropy %.2f. e.g. %s",
                            a.suspicious, 100 * share, a.total, a.uniqueSubs.size(), a.txt, a.maxEntropy,
                            truncate(a.example, 80))));
        }
        return alerts;
    }

    private static String truncate(String s, int n) { return s.length() <= n ? s : s.substring(0, n) + "..."; }
}
