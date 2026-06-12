package cryptosystem.phase1;
public class User {

    private final String userId;

    private RSAKeyPair rsaKeyPair;

    private Certificate certificate;

    public User(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }

    public RSAKeyPair getRsaKeyPair() {
        return rsaKeyPair;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setRsaKeyPair(RSAKeyPair rsaKeyPair) {
        this.rsaKeyPair = rsaKeyPair;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }
}
