package netanomaly;

import netanomaly.model.Conn;
import netanomaly.model.DnsQuery;

/** Small builders so tests read like the traffic they describe. */
public final class TestData {

    private TestData() {}

    public static Conn conn(double ts, String src, String dst, int dstPort, String state) {
        return conn(ts, src, dst, dstPort, "tcp", 100, 100, state);
    }

    public static Conn conn(double ts, String src, String dst, int dstPort, String proto,
                            long origBytes, long respBytes, String state) {
        return new Conn(ts, "C" + (long) (ts * 1000), src, 50000, dst, dstPort, proto, "-",
                1.0, origBytes, respBytes, state, 1, 1);
    }

    public static DnsQuery dns(double ts, String client, String query, String qtype) {
        return new DnsQuery(ts, "D" + (long) (ts * 1000), client, "192.168.1.1", query, qtype, "NOERROR");
    }
}
