package cryptosystem.phase1;

public class Certificate {
    private final String userId;
    private final int n;
    private final int e;
    private final int caSignature;

    public Certificate(String userId, int n, int e, int caSignature) {
        this.userId = userId;
        this.n = n;
        this.e = e;
        this.caSignature = caSignature;
    }

    public String getUserId() {
        return userId;
    }

    public int getN() {
        return n;
    }

    public int getE() {
        return e;
    }

    public int getCaSignature() {
        return caSignature;
    }

    @Override
    public String toString() {
        return "Certificate{userId='" + userId + "', n=" + n + ", e=" + e + ", signature_ca=" + caSignature + "}";
    }
}
