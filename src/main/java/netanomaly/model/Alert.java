package netanomaly.model;

/** A finding produced by one of the detectors. */
public record Alert(
        String detector,   // PORT_SCAN, BEACONING, DNS_TUNNELING, ...
        Severity severity,
        String src,
        String dst,
        double firstSeen,
        double lastSeen,
        double score,      // detector-specific strength, higher = more suspicious
        String details     // human-readable explanation
) {
    public enum Severity { LOW, MEDIUM, HIGH }
}
