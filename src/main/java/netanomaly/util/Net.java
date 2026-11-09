package netanomaly.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/** Small networking / math helpers shared by the detectors. */
public final class Net {

    private Net() {}

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /** True for RFC1918 / loopback / link-local / multicast - i.e. "inside" addresses. */
    public static boolean isInternal(String ip) {
        if (ip.contains(":")) { // IPv6
            String l = ip.toLowerCase();
            return l.equals("::1") || l.startsWith("fe80") || l.startsWith("fc")
                    || l.startsWith("fd") || l.startsWith("ff");
        }
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        int a, b;
        try { a = Integer.parseInt(p[0]); b = Integer.parseInt(p[1]); }
        catch (NumberFormatException e) { return false; }
        return a == 10 || a == 127
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && b == 168)
                || (a == 169 && b == 254)
                || (a >= 224) // multicast + broadcast
                || ip.equals("0.0.0.0");
    }

    /** Shannon entropy in bits per character. Random strings score ~4+, English words ~2.5-3.5. */
    public static double entropy(String s) {
        if (s.isEmpty()) return 0;
        int[] counts = new int[128];
        int n = 0;
        for (char c : s.toCharArray()) { if (c < 128) { counts[c]++; n++; } }
        double h = 0;
        for (int c : counts) {
            if (c == 0) continue;
            double p = (double) c / n;
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }

    public static String time(double epochSeconds) {
        return FMT.format(Instant.ofEpochMilli((long) (epochSeconds * 1000)));
    }

    public static String bytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024L * 1024) return String.format("%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format("%.1f MB", b / 1048576.0);
        return String.format("%.2f GB", b / 1073741824.0);
    }

    public static double mean(double[] x) {
        double s = 0; for (double v : x) s += v; return x.length == 0 ? 0 : s / x.length;
    }

    public static double std(double[] x) {
        if (x.length < 2) return 0;
        double m = mean(x), s = 0;
        for (double v : x) s += (v - m) * (v - m);
        return Math.sqrt(s / (x.length - 1));
    }

    public static double median(double[] x) {
        if (x.length == 0) return 0;
        double[] c = x.clone(); java.util.Arrays.sort(c);
        int n = c.length;
        return n % 2 == 1 ? c[n / 2] : (c[n / 2 - 1] + c[n / 2]) / 2.0;
    }
}
