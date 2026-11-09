package netanomaly.detect;

import netanomaly.model.Alert;
import netanomaly.model.Alert.Severity;
import netanomaly.model.Conn;
import netanomaly.util.Net;

import java.util.*;

/**
 * Compares against a baseline capture ("what normal looks like") and flags:
 *  - NEW_DEVICE:  an internal IP that never appeared during the baseline
 *  - NEW_SERVICE: an internal host:port that started answering connections
 *                 (e.g. someone opened SSH or a rogue web server)
 * Only runs when you pass --baseline.
 */
public class NewDeviceDetector {

    public List<Alert> run(List<Conn> conns, List<Conn> baseline) {
        List<Alert> alerts = new ArrayList<>();
        if (baseline == null || baseline.isEmpty()) return alerts;

        Set<String> knownHosts = new HashSet<>();
        Set<String> knownServices = new HashSet<>();
        for (Conn c : baseline) {
            if (Net.isInternal(c.srcIp())) knownHosts.add(c.srcIp());
            if (Net.isInternal(c.dstIp())) knownHosts.add(c.dstIp());
            if (Net.isInternal(c.dstIp()) && !c.failed()) knownServices.add(c.dstIp() + ":" + c.dstPort() + "/" + c.proto());
        }

        Map<String, double[]> newHosts = new TreeMap<>();     // ip -> [first, last, count]
        Map<String, double[]> newServices = new TreeMap<>();
        for (Conn c : conns) {
            String s = c.srcIp();
            if (Net.isInternal(s) && !knownHosts.contains(s) && !isMulticast(s)) track(newHosts, s, c.ts());
            if (Net.isInternal(c.dstIp()) && !c.failed() && !isMulticast(c.dstIp())) {
                String svc = c.dstIp() + ":" + c.dstPort() + "/" + c.proto();
                if (!knownServices.contains(svc)) track(newServices, svc, c.ts());
            }
        }

        newHosts.forEach((ip, t) -> alerts.add(new Alert("NEW_DEVICE", Severity.MEDIUM, ip, "-", t[0], t[1], t[2],
                String.format("Internal IP not seen during baseline; made %d connections", (int) t[2]))));
        newServices.forEach((svc, t) -> alerts.add(new Alert("NEW_SERVICE", Severity.LOW, "-", svc, t[0], t[1], t[2],
                String.format("Service accepted %d connections but never did during baseline", (int) t[2]))));
        return alerts;
    }

    private static void track(Map<String, double[]> m, String k, double ts) {
        double[] t = m.computeIfAbsent(k, x -> new double[]{ts, ts, 0});
        t[0] = Math.min(t[0], ts); t[1] = Math.max(t[1], ts); t[2]++;
    }

    private static boolean isMulticast(String ip) {
        if (ip.contains(":")) return ip.toLowerCase().startsWith("ff");
        int a = Integer.parseInt(ip.substring(0, ip.indexOf('.')));
        return a >= 224 || ip.endsWith(".255");
    }
}
