package cryptosystem.phase1;
public class CertificateAuthority {

    private final RSAKeyPair rsaKeyPair;

    public CertificateAuthority() {
        rsaKeyPair = CryptoUtils.generateRSAKeyPair();
    }

    public RSAKeyPair getRsaKeyPair() {
        return rsaKeyPair;
    }


    public Certificate issueCertificate(User user) {

        String string =
                user.getUserId()
                        + user.getRsaKeyPair().getN()
                        + user.getRsaKeyPair().getE();

        long signature =
                CryptoUtils.sign(string, rsaKeyPair);

        return new Certificate(
                user.getUserId(),
                (int) user.getRsaKeyPair().getN(),
                (int) user.getRsaKeyPair().getE(),
                (int) signature
        );
    }

    public boolean verifyCertificate(Certificate certificate) {

        String string =
                certificate.getUserId()
                        + certificate.getN()
                        + certificate.getE();

        return CryptoUtils.verify(
                string,
                certificate.getCaSignature(),
                rsaKeyPair.getE(),
                rsaKeyPair.getN()
        );
    }
}
