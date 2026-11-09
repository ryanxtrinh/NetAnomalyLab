package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.Conn;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static netanomaly.TestData.conn;
import static org.junit.jupiter.api.Assertions.*;

class BeaconDetectorTest {

    private final BeaconDetector detector = new BeaconDetector(new Config());

    @Test
    void regularCheckInsToExternalHostAreFlagged() {
        List<Conn> conns = new ArrayList<>();
        Random r = new Random(1);
        for (int i = 0; i < 40; i++) {
            double jitter = r.nextDouble() - 0.5; // +/- 0.5s on a 60s sleep
            conns.add(conn(i * 60.0 + jitter, "192.168.1.30", "45.33.32.156", 443, "tcp", 512, 1024, "SF"));
        }
        List<Alert> alerts = detector.run(conns);

        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("BEACONING", a.detector());
        assertEquals("45.33.32.156:443", a.dst());
        assertEquals(Alert.Severity.HIGH, a.severity());
        assertTrue(a.score() > 0.8, "score was " + a.score());
    }

    @Test
    void oneMissedCheckInDoesNotHideBeacon() {
        List<Conn> conns = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            if (i == 15) continue; // missed one: a single 120s gap
            conns.add(conn(i * 30.0, "192.168.1.30", "45.33.32.156", 8080, "tcp", 300, 300, "SF"));
        }
        assertEquals(1, detector.run(conns).size());
    }

    @Test
    void irregularHumanTrafficIsNotFlagged() {
        List<Conn> conns = new ArrayList<>();
        Random r = new Random(7);
        double t = 0;
        for (int i = 0; i < 40; i++) {
            t += 5 + r.nextDouble() * 300; // anywhere from 5s to 5 minutes apart
            conns.add(conn(t, "192.168.1.30", "151.101.1.69", 443, "tcp", 800 + r.nextInt(5000), 40000, "SF"));
        }
        assertTrue(detector.run(conns).isEmpty());
    }

    @Test
    void internalDestinationsSkippedByDefault() {
        List<Conn> conns = new ArrayList<>();
        for (int i = 0; i < 20; i++) conns.add(conn(i * 60.0, "192.168.1.30", "192.168.1.1", 53, "SF"));
        assertTrue(detector.run(conns).isEmpty());

        Config cfg = new Config();
        cfg.beaconExternalOnly = false;
        assertEquals(1, new BeaconDetector(cfg).run(conns).size());
    }

    @Test
    void tooFewConnectionsOrTooFastIsIgnored() {
        List<Conn> few = new ArrayList<>();
        for (int i = 0; i < 5; i++) few.add(conn(i * 60.0, "192.168.1.30", "8.8.4.4", 443, "SF"));
        assertTrue(detector.run(few).isEmpty());

        List<Conn> fast = new ArrayList<>();
        for (int i = 0; i < 50; i++) fast.add(conn(i * 1.0, "192.168.1.30", "8.8.4.4", 443, "SF"));
        assertTrue(detector.run(fast).isEmpty(), "sub-5s keepalives should be ignored");
    }
}
