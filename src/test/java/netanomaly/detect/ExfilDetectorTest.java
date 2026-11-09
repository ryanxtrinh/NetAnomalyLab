package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Conn;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static netanomaly.TestData.conn;
import static org.junit.jupiter.api.Assertions.*;

class ExfilDetectorTest {

    private static final long MB = 1024L * 1024;
    private final ExfilDetector detector = new ExfilDetector(new Config());

    @Test
    void largeUploadHeavyTransferIsFlagged() {
        List<Conn> conns = List.of(
                conn(100, "192.168.1.60", "203.0.113.9", 443, "tcp", 200 * MB, 2 * MB, "SF"),
                conn(200, "192.168.1.60", "203.0.113.9", 443, "tcp", 150 * MB, 1 * MB, "SF"));
        List<Alert> alerts = detector.run(conns, null);

        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("EXFILTRATION", a.detector());
        assertEquals("203.0.113.9", a.dst());
        assertEquals(350 * MB, (long) a.score());
        assertEquals(Alert.Severity.MEDIUM, a.severity()); // >= 3x the 100 MB minimum
    }

    @Test
    void gigabyteUploadIsHigh() {
        List<Conn> conns = List.of(conn(1, "10.0.0.5", "198.51.100.7", 22, "tcp", 1100 * MB, MB, "SF"));
        assertEquals(Alert.Severity.HIGH, detector.run(conns, null).get(0).severity());
    }

    @Test
    void downloadsAndSmallUploadsAreIgnored() {
        List<Conn> conns = List.of(
                conn(1, "192.168.1.60", "203.0.113.9", 443, "tcp", 5 * MB, 900 * MB, "SF"),   // streaming
                conn(2, "192.168.1.60", "203.0.113.10", 443, "tcp", 50 * MB, MB, "SF"),       // under 100 MB
                conn(3, "192.168.1.60", "203.0.113.11", 443, "tcp", 200 * MB, 100 * MB, "SF")); // ratio only 2x
        assertTrue(detector.run(conns, null).isEmpty());
    }

    @Test
    void internalToInternalCopiesAreIgnored() {
        List<Conn> conns = List.of(conn(1, "192.168.1.60", "192.168.1.2", 445, "tcp", 5000 * MB, MB, "SF"));
        assertTrue(detector.run(conns, null).isEmpty());
    }

    @Test
    void uploadSpikeAgainstBaseline() {
        List<Conn> baseline = new ArrayList<>();
        for (int h = 0; h < 24; h++) baseline.add(conn(h * 3600.0, "192.168.1.60", "203.0.113.20", 443, "tcp", MB / 2, MB, "SF"));

        // Spread across many destinations so no single pair trips EXFILTRATION
        List<Conn> now = new ArrayList<>();
        for (int i = 0; i < 20; i++) now.add(conn(i * 180.0, "192.168.1.60", "203.0.113." + (30 + i), 443, "tcp", 30 * MB, 30 * MB, "SF"));

        List<Alert> alerts = detector.run(now, baseline);
        assertEquals(1, alerts.size());
        assertEquals("UPLOAD_SPIKE", alerts.get(0).detector());
        assertEquals("192.168.1.60", alerts.get(0).src());
    }
}
