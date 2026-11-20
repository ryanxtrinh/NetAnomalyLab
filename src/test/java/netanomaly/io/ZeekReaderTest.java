package netanomaly.io;

import netanomaly.model.Conn;
import netanomaly.model.DnsQuery;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ZeekReaderTest {

    private static final String CONN_LOG = String.join("\n",
            "#separator \\x09",
            "#path\tconn",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount",
            "1700000000.123\tCabc1\t192.168.1.20\t51515\t93.184.216.34\t443\ttcp\tssl\t1.5\t1200\t54000\tSF\t10\t40",
            "1700000001.000\tCabc2\t192.168.1.20\t51516\t192.168.1.15\t23\ttcp\t-\t-\t-\t-\tS0\t1\t0",
            "garbage\tline\twith\tbad\tnumbers\tx\ttcp\t-\t-\t-\t-\tS0\t1\t0",
            "#close\t2023-11-14-22-13-20",
            "");

    private static Path write(String name, String content) throws IOException {
        Path dir = Files.createTempDirectory("zeek");
        Path p = dir.resolve(name);
        Files.writeString(p, content);
        return p;
    }

    @Test
    void readsConnLogAndHandlesMissingValues() throws IOException {
        List<Conn> conns = ZeekReader.readConn(write("conn.log", CONN_LOG));

        assertEquals(2, conns.size(), "malformed row should be skipped");
        Conn c = conns.get(0);
        assertEquals(1700000000.123, c.ts(), 1e-6);
        assertEquals("192.168.1.20", c.srcIp());
        assertEquals(443, c.dstPort());
        assertEquals("ssl", c.service());
        assertEquals(1200, c.origBytes());
        assertEquals(54000, c.respBytes());
        assertFalse(c.failed());

        Conn probe = conns.get(1);
        assertEquals(0.0, probe.duration(), 0.0);
        assertEquals(0, probe.origBytes());
        assertTrue(probe.failed());
    }

    @Test
    void columnOrderComesFromFieldsHeader() throws IOException {
        String log = "#fields\tid.resp_p\tid.orig_h\tts\tid.resp_h\tproto\tconn_state\n"
                + "8080\t10.0.0.1\t5.5\t10.0.0.2\tudp\tSF\n";
        Conn c = ZeekReader.readConn(write("conn.log", log)).get(0);
        assertEquals(8080, c.dstPort());
        assertEquals("10.0.0.1", c.srcIp());
        assertEquals(5.5, c.ts(), 1e-9);
        assertEquals("-", c.uid(), "absent column defaults to '-'");
    }

    @Test
    void readsGzippedLogs() throws IOException {
        Path dir = Files.createTempDirectory("zeek");
        Path p = dir.resolve("conn.00:00:00-01:00:00.log.gz");
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(p))) {
            out.write(CONN_LOG.getBytes(StandardCharsets.UTF_8));
        }
        assertEquals(2, ZeekReader.readConn(p).size());
    }

    @Test
    void dnsLogDropsEmptyQueries() throws IOException {
        String log = "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\tqtype_name\trcode_name\n"
                + "1.0\tD1\t192.168.1.20\t192.168.1.1\twww.example.com\tA\tNOERROR\n"
                + "2.0\tD2\t192.168.1.20\t192.168.1.1\t-\t-\t-\n";
        List<DnsQuery> qs = ZeekReader.readDns(write("dns.log", log));
        assertEquals(1, qs.size());
        assertEquals("www.example.com", qs.get(0).query());
        assertEquals("A", qs.get(0).qtypeName());
    }

    @Test
    void jsonLogsGiveHelpfulError() throws IOException {
        Path p = write("conn.log", "{\"ts\":1.0,\"uid\":\"C1\"}\n");
        IOException e = assertThrows(IOException.class, () -> ZeekReader.readConn(p));
        assertTrue(e.getMessage().contains("JSON"));
    }

    @Test
    void fileWithoutHeaderIsRejected() throws IOException {
        Path p = write("conn.log", "1.0\tC1\t10.0.0.1\n");
        assertThrows(IOException.class, () -> ZeekReader.readConn(p));
    }
}
