package netanomaly.ml;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class IsolationForestTest {

    private static double[][] cluster(int n, long seed) {
        Random r = new Random(seed);
        double[][] d = new double[n][];
        for (int i = 0; i < n; i++) d[i] = new double[]{r.nextGaussian(), r.nextGaussian(), r.nextGaussian()};
        return d;
    }

    @Test
    void outlierScoresHigherThanInlier() {
        IsolationForest f = new IsolationForest(100, 256, 42);
        f.fit(cluster(1000, 1));

        double inlier = f.score(new double[]{0, 0, 0});
        double outlier = f.score(new double[]{8, -8, 8});

        assertTrue(outlier > 0.6, "outlier score " + outlier);
        assertTrue(inlier < 0.5, "inlier score " + inlier);
        assertTrue(outlier > inlier);
    }

    @Test
    void scoresAreBetweenZeroAndOne() {
        IsolationForest f = new IsolationForest(50, 128, 7);
        double[][] data = cluster(500, 2);
        f.fit(data);
        for (double[] p : data) {
            double s = f.score(p);
            assertTrue(s > 0 && s < 1, "score out of range: " + s);
        }
    }

    @Test
    void sameSeedGivesSameScores() {
        double[][] data = cluster(300, 3);
        IsolationForest a = new IsolationForest(30, 64, 99);
        IsolationForest b = new IsolationForest(30, 64, 99);
        a.fit(data);
        b.fit(data);
        double[] p = {2.5, -1, 0.3};
        assertEquals(a.score(p), b.score(p), 0.0);
    }

    @Test
    void constantDataDoesNotCrash() {
        double[][] data = new double[100][];
        for (int i = 0; i < data.length; i++) data[i] = new double[]{1, 1, 1};
        IsolationForest f = new IsolationForest(10, 64, 1);
        f.fit(data);
        double s = f.score(new double[]{1, 1, 1});
        assertFalse(Double.isNaN(s));
    }
}
