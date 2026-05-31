package cryptosystem.phase1;

public class RsaPublicKey {
    private final int n;
    private final int e;

    public RsaPublicKey(int n, int e) {
        this.n = n;
        this.e = e;
    }

    public int getN() {
        return n;
    }

    public int getE() {
        return e;
    }

    @Override
    public String toString() {
        return "(n=" + n + ", e=" + e + ")";
    }
}
