package netanomaly;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {

    @Test
    void nullPathGivesDefaults() throws IOException {
        Config c = Config.load(null);
        assertEquals(25, c.scanPortThreshold);
        assertTrue(c.beaconExternalOnly);
    }

    @Test
    void overridesEveryFieldType() throws IOException {
        Path p = Files.createTempFile("cfg", ".properties");
        Files.writeString(p, "scanPortThreshold = 40\nexfilMinBytes=1048576\nbeaconMaxCv=0.25\n"
                + "beaconExternalOnly=false\nnotARealKey=1\n");
        Config c = Config.load(p);
        assertEquals(40, c.scanPortThreshold);
        assertEquals(1048576L, c.exfilMinBytes);
        assertEquals(0.25, c.beaconMaxCv, 1e-9);
        assertFalse(c.beaconExternalOnly);
    }

    @Test
    void badNumberIsReported() throws IOException {
        Path p = Files.createTempFile("cfg", ".properties");
        Files.writeString(p, "mlTrees=lots\n");
        IOException e = assertThrows(IOException.class, () -> Config.load(p));
        assertTrue(e.getMessage().contains("mlTrees"));
    }
}
