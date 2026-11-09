package netanomaly;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Detection thresholds. Defaults are reasonable for a small home/lab network.
 * Override any of them with a .properties file:  analyze ... --config my.properties
 * (see config.example.properties). Tuning these is part of the project -
 * write down what you changed and why in your report.
 */
public final class Config {

    // Port scan: distinct ports / hosts touched by one source inside one time window
    public double scanWindowSec = 60;
    public int scanPortThreshold = 25;   // vertical scan: many ports on one host
    public int scanHostThreshold = 20;   // horizontal sweep: one port across many hosts

    // Beaconing: regular check-ins to the same destination
    public int beaconMinConns = 10;
    public double beaconMaxCv = 0.15;        // coefficient of variation of intervals (std/mean)
    public double beaconMinIntervalSec = 5;  // ignore sub-5s chatter (streaming, keepalives)
    public boolean beaconExternalOnly = true;

    // DNS tunneling
    public int dnsMinSubdomainLen = 30;
    public double dnsMinEntropy = 3.5;
    public int dnsMinSuspiciousQueries = 10; // per client + base domain

    // Exfiltration: big uploads to the internet
    public long exfilMinBytes = 100L * 1024 * 1024; // 100 MB
    public double exfilUploadRatio = 5.0;           // uploaded >= 5x downloaded

    // Isolation Forest
    public int mlTrees = 100;
    public int mlSampleSize = 256;
    public double mlScoreThreshold = 0.62;
    public int mlMaxAlerts = 15;
    public long mlSeed = 42;

    public static Config load(Path file) throws IOException {
        Config c = new Config();
        if (file == null) return c;
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file)) { p.load(r); }
        for (String key : p.stringPropertyNames()) {
            try {
                var f = Config.class.getField(key);
                String v = p.getProperty(key).trim();
                Class<?> t = f.getType();
                if (t == int.class) f.setInt(c, Integer.parseInt(v));
                else if (t == long.class) f.setLong(c, Long.parseLong(v));
                else if (t == double.class) f.setDouble(c, Double.parseDouble(v));
                else if (t == boolean.class) f.setBoolean(c, Boolean.parseBoolean(v));
            } catch (NoSuchFieldException e) {
                System.err.println("Unknown config key ignored: " + key);
            } catch (IllegalAccessException | NumberFormatException e) {
                throw new IOException("Bad value for " + key + ": " + p.getProperty(key));
            }
        }
        return c;
    }
}
