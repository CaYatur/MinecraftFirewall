namespace MinecraftFirewall.Proxy.Anomaly;

/// <summary>
/// An isolation forest: an ensemble of random binary trees that scores how easy a point is to
/// separate from the rest of the data.
///
/// The idea is simpler than most anomaly detectors, which is exactly why it suits a firewall. Build a
/// tree by repeatedly picking a random feature and a random split point between that feature's
/// observed minimum and maximum. Unusual points end up alone quickly, near the root; ordinary points
/// take many splits to isolate because they sit among neighbours. Average the depth at which a point
/// gets isolated across many trees and you have a score, with no labelled examples of attacks needed —
/// which matters here, because nobody has a labelled corpus of Minecraft attack traffic, and a
/// detector that needed one would never be trained.
///
/// Implemented directly rather than through a machine-learning runtime. The whole algorithm is a
/// hundred lines, and adding a framework dependency to a Windows service that has to install without
/// prerequisites would cost far more than it saves.
///
/// The scoring formula is Liu, Ting and Zhou's (ICDM 2008): normalise the average isolation depth by
/// the average depth of an unsuccessful binary-search in a tree of the same size, then map it to
/// 2^(-normalised). Around 0.5 means "as ordinary as anything else here"; approaching 1 means "nothing
/// else in the training data looked like this".
/// </summary>
public sealed class IsolationForest
{
    private readonly Node[] _roots;
    private readonly int _sampleSize;

    private IsolationForest(Node[] roots, int sampleSize)
    {
        _roots = roots;
        _sampleSize = sampleSize;
    }

    public int TreeCount => _roots.Length;

    /// <summary>
    /// Builds a forest from observed samples.
    ///
    /// Each tree sees a small random subsample rather than everything, which is the counter-intuitive
    /// part of the algorithm and the reason it works: a small sample makes anomalies stand out, while
    /// a large one lets clusters of near-duplicates hide them. 256 is the figure the original paper
    /// settles on and it is not worth second-guessing here.
    /// </summary>
    public static IsolationForest Train(IReadOnlyList<double[]> samples, int trees = 64, int sampleSize = 256, int seed = 20260825)
    {
        if (samples.Count == 0)
            throw new ArgumentException("An isolation forest cannot be trained on no samples.", nameof(samples));

        int effectiveSample = Math.Min(sampleSize, samples.Count);
        int heightLimit = Math.Max(1, (int)Math.Ceiling(Math.Log2(Math.Max(2, effectiveSample))));

        var random = new Random(seed);
        var roots = new Node[trees];

        for (int i = 0; i < trees; i++)
        {
            double[][] subsample = new double[effectiveSample][];
            for (int j = 0; j < effectiveSample; j++)
                subsample[j] = samples[random.Next(samples.Count)];

            roots[i] = Build(subsample, 0, heightLimit, random);
        }

        return new IsolationForest(roots, effectiveSample);
    }

    /// <summary>Scores a point in [0, 1]. Higher means more isolated — more unlike the training data.
    /// Around 0.5 is unremarkable; the paper treats values well above 0.6 as worth attention.</summary>
    public double Score(double[] point)
    {
        double totalDepth = 0;
        foreach (Node root in _roots)
            totalDepth += PathLength(root, point, 0);

        double average = totalDepth / _roots.Length;
        double normaliser = AveragePathLength(_sampleSize);

        return normaliser <= 0 ? 0.5 : Math.Pow(2, -average / normaliser);
    }

    private static Node Build(double[][] samples, int depth, int heightLimit, Random random)
    {
        // A leaf either because the tree is deep enough or because there is nothing left to split. The
        // remaining count is kept so the score can account for the sub-tree that was not built out —
        // without it, every point reaching the height limit would look equally ordinary.
        if (depth >= heightLimit || samples.Length <= 1)
            return Node.Leaf(samples.Length);

        // Only features that actually vary here are candidates.
        //
        // Picking blindly and giving up when the choice turns out constant looks equivalent and is
        // not: with ten features of which two vary, four splits in five would end the branch
        // immediately, and the trees come out so shallow that everything scores alike. That was
        // measured, not guessed — an obvious outlier scored *below* ordinary points until this changed,
        // because neither had been isolated by anything.
        int dimensions = samples[0].Length;
        Span<int> usable = stackalloc int[dimensions];
        int usableCount = 0;

        for (int f = 0; f < dimensions; f++)
        {
            double lo = double.MaxValue, hi = double.MinValue;
            foreach (double[] sample in samples)
            {
                lo = Math.Min(lo, sample[f]);
                hi = Math.Max(hi, sample[f]);
            }

            if (hi - lo >= 1e-12)
                usable[usableCount++] = f;
        }

        // Every sample agrees on every feature — genuinely nothing left to separate.
        if (usableCount == 0)
            return Node.Leaf(samples.Length);

        int feature = usable[random.Next(usableCount)];

        double min = double.MaxValue, max = double.MinValue;
        foreach (double[] sample in samples)
        {
            min = Math.Min(min, sample[feature]);
            max = Math.Max(max, sample[feature]);
        }

        double threshold = min + (random.NextDouble() * (max - min));

        var left = new List<double[]>();
        var right = new List<double[]>();
        foreach (double[] sample in samples)
            (sample[feature] < threshold ? left : right).Add(sample);

        return Node.Split(feature, threshold,
            Build([.. left], depth + 1, heightLimit, random),
            Build([.. right], depth + 1, heightLimit, random));
    }

    private static double PathLength(Node node, double[] point, int depth)
    {
        while (!node.IsLeaf)
        {
            node = point[node.Feature] < node.Threshold ? node.Left! : node.Right!;
            depth++;
        }

        // Adding the expected depth of the sub-tree that was never built keeps a point that stopped at
        // the height limit from being scored as though it had been fully isolated there.
        return depth + AveragePathLength(node.Size);
    }

    /// <summary>
    /// Expected depth of an unsuccessful search in a random binary tree of n nodes — the normalising
    /// term from the paper. Without it a score would depend on how much data the forest happened to be
    /// trained on, and could not be compared between servers or between restarts.
    /// </summary>
    private static double AveragePathLength(int n)
    {
        if (n <= 1)
            return 0;

        const double euler = 0.5772156649;
        return (2 * (Math.Log(n - 1) + euler)) - (2.0 * (n - 1) / n);
    }

    private sealed class Node
    {
        public int Feature;
        public double Threshold;
        public Node? Left;
        public Node? Right;
        public int Size;

        public bool IsLeaf => Left is null;

        public static Node Leaf(int size) => new() { Size = size };

        public static Node Split(int feature, double threshold, Node left, Node right) =>
            new() { Feature = feature, Threshold = threshold, Left = left, Right = right };
    }
}
