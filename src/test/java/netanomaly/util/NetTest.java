package netanomaly.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetTest {

    @Test
    void privateAndSpecialIpv4RangesAreInternal() {
        for (String ip : new String[]{"10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.20",
                "127.0.0.1", "169.254.10.10", "224.0.0.251", "255.255.255.255", "0.0.0.0"}) {
            assertTrue(Net.isInternal(ip), ip + " should be internal");
        }
    }

    @Test
    void publicIpv4IsExternal() {
        for (String ip : new String[]{"8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.1.1", "1.1.1.1"}) {
            assertFalse(Net.isInternal(ip), ip + " should be external");
        }
    }

    @Test
    void ipv6Classification() {
        assertTrue(Net.isInternal("::1"));
        assertTrue(Net.isInternal("fe80::1"));
        assertTrue(Net.isInternal("fd00::abcd"));
        assertTrue(Net.isInternal("ff02::fb"));
        assertFalse(Net.isInternal("2001:4860:4860::8888"));
    }

    @Test
    void malformedAddressIsNotInternal() {
        assertFalse(Net.isInternal("not-an-ip"));
        assertFalse(Net.isInternal("10.0.0"));
    }

    @Test
    void entropyOfKnownStrings() {
        assertEquals(0.0, Net.entropy(""), 1e-9);
        assertEquals(0.0, Net.entropy("aaaa"), 1e-9);
        assertEquals(1.0, Net.entropy("abab"), 1e-9);
        assertEquals(2.0, Net.entropy("abcd"), 1e-9);
        assertTrue(Net.entropy("mzxw6ytboi4dmnrrgu3tcmzx") > Net.entropy("wwwgooglecom"));
    }

    @Test
    void statsHelpers() {
        double[] x = {2, 4, 4, 4, 5, 5, 7, 9};
        assertEquals(5.0, Net.mean(x), 1e-9);
        assertEquals(4.5, Net.median(x), 1e-9);
        assertEquals(2.138, Net.std(x), 1e-3); // sample std dev
        assertEquals(3.0, Net.median(new double[]{5, 1, 3}), 1e-9);
        assertEquals(0.0, Net.mean(new double[0]), 1e-9);
        assertEquals(0.0, Net.std(new double[]{42}), 1e-9);
    }

    @Test
    void medianDoesNotReorderInput() {
        double[] x = {3, 1, 2};
        Net.median(x);
        assertArrayEquals(new double[]{3, 1, 2}, x, 1e-9);
    }

    @Test
    void humanReadableBytes() {
        assertEquals("512 B", Net.bytes(512));
        assertEquals("1.5 KB", Net.bytes(1536));
        assertEquals("100.0 MB", Net.bytes(100L * 1024 * 1024));
        assertEquals("2.00 GB", Net.bytes(2L * 1024 * 1024 * 1024));
    }
}
