package netanomaly.model;

/**
 * One connection from a Zeek conn.log.
 * Zeek summarizes every TCP/UDP/ICMP "conversation" as one row.
 */
public record Conn(
        double ts,          // start time (Unix epoch seconds)
        String uid,         // Zeek's unique connection ID
        String srcIp,       // id.orig_h  - who started the connection
        int srcPort,        // id.orig_p
        String dstIp,       // id.resp_h  - who answered
        int dstPort,        // id.resp_p
        String proto,       // tcp / udp / icmp
        String service,     // protocol Zeek detected (http, dns, ssl...), or "-"
        double duration,    // seconds
        long origBytes,     // bytes sent by the originator (upload)
        long respBytes,     // bytes sent by the responder (download)
        String connState,   // S0, SF, REJ, RSTO... (see README)
        long origPkts,
        long respPkts
) {
    /** States that mean the connection never really completed (typical of scans). */
    public boolean failed() {
        return switch (connState) {
            case "S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH" -> true;
            default -> false;
        };
    }
}
