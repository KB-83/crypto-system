package cryptosystem.phase1;
public class RSAKeyPair {

    private final long n;
    private final long e;
    private final long d;

    public RSAKeyPair(long n, long e, long d) {
        this.n = n;
        this.e = e;
        this.d = d;
    }

    public long getN() {
        return n;
    }

    public long getE() {
        return e;
    }

    public long getD() {
        return d;
    }
}