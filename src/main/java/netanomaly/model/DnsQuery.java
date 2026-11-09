package netanomaly.model;

/** One DNS request from a Zeek dns.log. */
public record DnsQuery(
        double ts,
        String uid,
        String clientIp,   // id.orig_h
        String serverIp,   // id.resp_h
        String query,      // e.g. www.example.com
        String qtypeName,  // A, AAAA, TXT, CNAME...
        String rcodeName   // NOERROR, NXDOMAIN...
) {}
