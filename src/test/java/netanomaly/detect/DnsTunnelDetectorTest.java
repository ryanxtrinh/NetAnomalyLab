package netanomaly.detect;

import netanomaly.Config;
import netanomaly.model.Alert;
import netanomaly.model.DnsQuery;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static netanomaly.TestData.dns;
import static org.junit.jupiter.api.Assertions.*;

class DnsTunnelDetectorTest {

    private final DnsTunnelDetector detector = new DnsTunnelDetector(new Config());

    private static String randomLabel(Random r, int len) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz234567"; // base32, like real tunneling tools
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
        return sb.toString();
    }

    @Test
    void encodedSubdomainsAreFlagged() {
        Random r = new Random(3);
        List<DnsQuery> qs = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            String name = randomLabel(r, 40) + "." + randomLabel(r, 12) + ".update-check.xyz";
            qs.add(dns(i, "192.168.1.40", name, i % 2 == 0 ? "TXT" : "A"));
        }
        List<Alert> alerts = detector.run(qs);

        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("DNS_TUNNELING", a.detector());
        assertEquals("192.168.1.40", a.src());
        assertEquals("update-check.xyz", a.dst());
        assertEquals(40, a.score(), 1e-9);
        assertEquals(Alert.Severity.MEDIUM, a.severity());
        assertTrue(a.details().contains("20 TXT"), a.details());
    }

    @Test
    void ordinaryLookupsAreNotFlagged() {
        String[] names = {"www.google.com", "api.spotify.com", "outlook.office365.com",
                "fonts.gstatic.com", "en.wikipedia.org", "clients4.google.com"};
        List<DnsQuery> qs = new ArrayList<>();
        for (int i = 0; i < 200; i++) qs.add(dns(i, "192.168.1.40", names[i % names.length], "A"));
        assertTrue(detector.run(qs).isEmpty());
    }

    @Test
    void reverseLookupsAndMdnsAreSkipped() {
        Random r = new Random(5);
        List<DnsQuery> qs = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            qs.add(dns(i, "192.168.1.40", randomLabel(r, 40) + ".x.in-addr.arpa", "PTR"));
            qs.add(dns(i, "192.168.1.40", randomLabel(r, 40) + "._tcp.local", "PTR"));
        }
        assertTrue(detector.run(qs).isEmpty());
    }

    @Test
    void longButLowEntropyNamesAreNotSuspicious() {
        List<DnsQuery> qs = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            qs.add(dns(i, "192.168.1.40", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + i + ".cdn.example.com", "A"));
        }
        assertTrue(detector.run(qs).isEmpty());
    }
}
