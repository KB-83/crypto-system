package cryptosystem.phase1;

public class Phase1ServiceImpl implements Phase1Service {

    private final CertificateAuthority ca;
    private final User userA;
    private final User userB;

    public Phase1ServiceImpl() {

        ca = new CertificateAuthority();

        userA = new User("A");
        userB = new User("B");

        userA.setRsaKeyPair(CryptoUtils.generateRSAKeyPair());
        userB.setRsaKeyPair(CryptoUtils.generateRSAKeyPair());

        userA.setCertificate(ca.issueCertificate(userA));
        userB.setCertificate(ca.issueCertificate(userB));
    }

    @Override
    public RsaPublicKey getCaPublicKey() {
        return new RsaPublicKey(
                (int) ca.getRsaKeyPair().getN(),
                (int) ca.getRsaKeyPair().getE()
        );
    }

    @Override
    public RsaPublicKey getUserAPublicKey() {
        return new RsaPublicKey(
                (int) userA.getRsaKeyPair().getN(),
                (int) userA.getRsaKeyPair().getE()
        );
    }

    @Override
    public RsaPublicKey getUserBPublicKey() {
        return new RsaPublicKey(
                (int) userB.getRsaKeyPair().getN(),
                (int) userB.getRsaKeyPair().getE()
        );
    }

    @Override
    public Certificate issueCertificate(
            String userId,
            RsaPublicKey publicKey) {

        if ("A".equals(userId)) {
            return userA.getCertificate();
        }

        return userB.getCertificate();
    }

    @Override
    public boolean verifyCertificate(
            Certificate certificate,
            RsaPublicKey ignored) {

        return ca.verifyCertificate(certificate);
    }

    public User getUserA() {
        return userA;
    }

    public User getUserB() {
        return userB;
    }
    public CertificateAuthority getCertificateAuthority() {
        return ca;
    }
}