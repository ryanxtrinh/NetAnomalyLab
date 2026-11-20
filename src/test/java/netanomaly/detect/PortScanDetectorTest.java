package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Conn;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static netanomaly.TestData.conn;
import static org.junit.jupiter.api.Assertions.*;

class PortScanDetectorTest {

    private final PortScanDetector detector = new PortScanDetector(new Config());

    @Test
    void verticalScanIsFlagged() {
        List<Conn> conns = new ArrayList<>();
        for (int port = 1; port <= 100; port++) {
            conns.add(conn(1000 + port * 0.1, "192.168.1.50", "192.168.1.15", port, "REJ"));
        }
        List<Alert> alerts = detector.run(conns);

        Alert a = alerts.stream().filter(x -> x.details().startsWith("Vertical")).findFirst().orElseThrow();
        assertEquals("PORT_SCAN", a.detector());
        assertEquals("192.168.1.50", a.src());
        assertEquals("192.168.1.15", a.dst());
        assertEquals(100, a.score(), 1e-9);
        assertEquals(Alert.Severity.MEDIUM, a.severity());
        assertTrue(a.details().contains("100% of 100 attempts failed"), a.details());
    }

    @Test
    void horizontalSweepIsFlagged() {
        List<Conn> conns = new ArrayList<>();
        for (int host = 1; host <= 50; host++) {
            conns.add(conn(2000 + host * 0.2, "192.168.1.50", "192.168.1." + host, 22, "S0"));
        }
        List<Alert> alerts = detector.run(conns);

        Alert a = alerts.stream().filter(x -> x.details().startsWith("Horizontal")).findFirst().orElseThrow();
        assertEquals("port 22/tcp", a.dst());
        assertEquals(50, a.score(), 1e-9);
        assertEquals(Alert.Severity.MEDIUM, a.severity());
    }

    @Test
    void normalBrowsingIsNotFlagged() {
        List<Conn> conns = new ArrayList<>();
        int[] ports = {80, 443, 53, 443, 443, 80};
        for (int i = 0; i < ports.length; i++) {
            conns.add(conn(3000 + i * 5, "192.168.1.20", "93.184.216.34", ports[i], "SF"));
        }
        assertTrue(detector.run(conns).isEmpty());
    }

    @Test
    void slowScanBelowWindowThresholdIsIgnored() {
        // 30 ports, but one per minute: never more than 1-2 in a 60s window
        List<Conn> conns = new ArrayList<>();
        for (int port = 1; port <= 30; port++) {
            conns.add(conn(port * 61.0, "192.168.1.50", "192.168.1.15", port, "REJ"));
        }
        assertTrue(detector.run(conns).isEmpty());
    }

    @Test
    void scanAcrossSeveralWindowsProducesOneAlert() {
        List<Conn> conns = new ArrayList<>();
        for (int port = 1; port <= 300; port++) {
            conns.add(conn(port * 0.5, "10.0.0.9", "10.0.0.1", port, "S0")); // 150s total
        }
        long vertical = detector.run(conns).stream().filter(a -> a.details().startsWith("Vertical")).count();
        assertEquals(1, vertical);
    }

    @Test
    void icmpIsIgnored() {
        List<Conn> conns = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            conns.add(conn(i * 0.1, "192.168.1.50", "192.168.1." + (i % 250), 0, "icmp", 64, 64, "OTH"));
        }
        assertTrue(detector.run(conns).isEmpty());
    }
}
