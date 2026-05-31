package cryptosystem.phase1;

public interface Phase1Service {
    RsaPublicKey getCaPublicKey();

    RsaPublicKey getUserAPublicKey();

    RsaPublicKey getUserBPublicKey();

    Certificate issueCertificate(String userId, RsaPublicKey publicKey);

    boolean verifyCertificate(Certificate certificate, RsaPublicKey caPublicKey);
}
