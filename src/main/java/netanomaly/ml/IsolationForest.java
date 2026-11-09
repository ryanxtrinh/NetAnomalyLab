package netanomaly.ml;

import java.util.Random;

/**
 * Isolation Forest (Liu, Ting & Zhou, 2008), written from scratch - no libraries.
 *
 * Idea: build many random trees that split the data on a random feature at a random
 * value. Weird points are "easy to isolate" - they end up alone after only a few
 * splits, so their average path length is short. Normal points sit in dense clusters
 * and need many splits.
 *
 * score(x) = 2^( -E[pathLength(x)] / c(n) )
 *   ~1.0  -> very anomalous
 *   ~0.5  -> nothing special
 *   <0.5  -> very normal
 */
public class IsolationForest {

    private final int numTrees, sampleSize;
    private final Random rnd;
    private Node[] trees;
    private int heightLimit, fittedN;

    public IsolationForest(int numTrees, int sampleSize, long seed) {
        this.numTrees = numTrees;
        this.sampleSize = sampleSize;
        this.rnd = new Random(seed);
    }

    private static final class Node {
        int feature = -1;          // -1 = leaf
        double split;
        Node left, right;
        int size;                  // points that reached this leaf
    }

    public void fit(double[][] data) {
        int n = Math.min(sampleSize, data.length);
        fittedN = n;
        heightLimit = (int) Math.ceil(Math.log(Math.max(2, n)) / Math.log(2));
        trees = new Node[numTrees];
        for (int t = 0; t < numTrees; t++) {
            double[][] sample = new double[n][];
            for (int i = 0; i < n; i++) sample[i] = data[rnd.nextInt(data.length)];
            trees[t] = build(sample, 0);
        }
    }

    private Node build(double[][] x, int depth) {
        Node node = new Node();
        if (depth >= heightLimit || x.length <= 1) { node.size = x.length; return node; }

        int dims = x[0].length;
        // Pick a random feature that actually varies in this subset
        for (int attempt = 0; attempt < dims * 2; attempt++) {
            int f = rnd.nextInt(dims);
            double lo = Double.MAX_VALUE, hi = -Double.MAX_VALUE;
            for (double[] row : x) { lo = Math.min(lo, row[f]); hi = Math.max(hi, row[f]); }
            if (hi <= lo) continue;

            double split = lo + rnd.nextDouble() * (hi - lo);
            int nl = 0;
            for (double[] row : x) if (row[f] < split) nl++;
            double[][] l = new double[nl][], r = new double[x.length - nl][];
            int il = 0, ir = 0;
            for (double[] row : x) { if (row[f] < split) l[il++] = row; else r[ir++] = row; }

            node.feature = f; node.split = split;
            node.left = build(l, depth + 1);
            node.right = build(r, depth + 1);
            return node;
        }
        node.size = x.length; // all features constant -> leaf
        return node;
    }

    public double score(double[] point) {
        double total = 0;
        for (Node t : trees) total += pathLength(point, t, 0);
        double avg = total / trees.length;
        return Math.pow(2, -avg / c(fittedN));
    }

    private double pathLength(double[] p, Node node, int depth) {
        if (node.feature == -1) return depth + c(node.size);
        return pathLength(p, p[node.feature] < node.split ? node.left : node.right, depth + 1);
    }

    /** Average path length of an unsuccessful search in a binary search tree of n points. */
    private static double c(int n) {
        if (n <= 1) return 0;
        if (n == 2) return 1;
        double harmonic = Math.log(n - 1) + 0.5772156649;
        return 2 * harmonic - 2.0 * (n - 1) / n;
    }
}
