package cryptosystem.phase2;
import java.util.Random;
import cryptosystem.phase1.*;

public class DiffieHellman {

    private static final long P = 65521;
    private static final long G = 11;



    public static int generateSharedKey(
            User A,
            User B,
            CertificateAuthority ca) {

        if (!ca.verifyCertificate(A.getCertificate())) {
            throw new IllegalStateException("A certificate INVALID");
        }

        if (!ca.verifyCertificate(B.getCertificate())) {
            throw new IllegalStateException("B certificate INVALID");
        }

        Random random = new Random();

        long a = 2 + random.nextInt(65519);
        long b = 2 + random.nextInt(65519);

        long A_pub = CryptoUtils.modPower(G, a, P);
        long B_pub = CryptoUtils.modPower(G, b, P);

        long sigA =
                CryptoUtils.sign(
                        String.valueOf(A_pub),
                        A.getRsaKeyPair());

        long sigB =
                CryptoUtils.sign(
                        String.valueOf(B_pub),
                        B.getRsaKeyPair());

        boolean validA =
                CryptoUtils.verify(
                        String.valueOf(A_pub),
                        sigA,
                        A.getCertificate().getE(),
                        A.getCertificate().getN());

        boolean validB =
                CryptoUtils.verify(
                        String.valueOf(B_pub),
                        sigB,
                        B.getCertificate().getE(),
                        B.getCertificate().getN());

        if (!validA || !validB) {
            throw new IllegalStateException(
                    "DH authentication failed");
        }

        long KA =
                CryptoUtils.modPower(B_pub, a, P);

        long KB =
                CryptoUtils.modPower(A_pub, b, P);

        if (KA != KB) {
            throw new IllegalStateException(
                    "Shared key mismatch");
        }

        return (int) (KA & 0xFFFF);
    }
}
