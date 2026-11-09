package netanomaly.detect;

import netanomaly.model.Alert;
import netanomaly.model.Conn;
import org.junit.jupiter.api.Test;

import java.util.List;

import static netanomaly.TestData.conn;
import static org.junit.jupiter.api.Assertions.*;

class NewDeviceDetectorTest {

    private final NewDeviceDetector detector = new NewDeviceDetector();

    private final List<Conn> baseline = List.of(
            conn(1, "192.168.1.20", "8.8.8.8", 53, "SF"),
            conn(2, "192.168.1.20", "192.168.1.10", 445, "SF"));

    @Test
    void doesNothingWithoutBaseline() {
        assertTrue(detector.run(List.of(conn(1, "192.168.1.99", "8.8.8.8", 53, "SF")), null).isEmpty());
        assertTrue(detector.run(List.of(conn(1, "192.168.1.99", "8.8.8.8", 53, "SF")), List.of()).isEmpty());
    }

    @Test
    void flagsUnknownInternalDevice() {
        List<Alert> alerts = detector.run(List.of(
                conn(10, "192.168.1.99", "8.8.8.8", 53, "SF"),
                conn(20, "192.168.1.99", "1.1.1.1", 443, "SF")), baseline);

        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("NEW_DEVICE", a.detector());
        assertEquals("192.168.1.99", a.src());
        assertEquals(2, a.score(), 1e-9);
        assertEquals(10, a.firstSeen(), 1e-9);
        assertEquals(20, a.lastSeen(), 1e-9);
    }

    @Test
    void flagsNewlyOpenedServiceButNotFailedProbes() {
        List<Alert> alerts = detector.run(List.of(
                conn(10, "192.168.1.20", "192.168.1.10", 22, "SF"),    // SSH newly answering
                conn(11, "192.168.1.20", "192.168.1.10", 3389, "REJ"), // closed port, ignore
                conn(12, "192.168.1.20", "192.168.1.10", 445, "SF")),  // already known
                baseline);

        assertEquals(1, alerts.size());
        assertEquals("NEW_SERVICE", alerts.get(0).detector());
        assertEquals("192.168.1.10:22/tcp", alerts.get(0).dst());
    }

    @Test
    void ignoresMulticastAndBroadcast() {
        List<Alert> alerts = detector.run(List.of(
                conn(1, "192.168.1.20", "224.0.0.251", 5353, "udp", 50, 0, "S0"),
                conn(2, "192.168.1.20", "192.168.1.255", 137, "udp", 50, 50, "SF")), baseline);
        assertTrue(alerts.isEmpty());
    }
}
