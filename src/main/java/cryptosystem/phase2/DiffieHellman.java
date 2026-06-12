package cryptosystem.phase2;
import java.util.Random;
import cryptosystem.phase1.*;

public class DiffieHellman {

    private static final long P = 65521;
    private static final long G = 11;

    public static void diffie_hellman_exchange(User A, User B, CertificateAuthority ca) {

        System.out.println("\n=== Diffie-Hellman Authenticated Protocol Start ===\n");

        System.out.println("Verifying certificate of A...");
        if (!ca.verifyCertificate(A.getCertificate())) {
            System.out.println("A certificate INVALID");
            return;
        }
        System.out.println("A certificate VALID\n");

        System.out.println("Verifying certificate of B...");
        if (!ca.verifyCertificate(B.getCertificate())) {
            System.out.println("B certificate INVALID");
            return;
        }
        System.out.println("B certificate VALID\n");

        Random random = new Random();

        long a = 2 + random.nextInt(65519);
        long b = 2 + random.nextInt(65519);

        System.out.println("Private values generated:");
        System.out.println("a (Alice secret) generated");
        System.out.println("b (Bob secret) generated\n");

        long A_pub = CryptoUtils.modPower(G, a, P);
        long B_pub = CryptoUtils.modPower(G, b, P);

        System.out.println("Public values computed:");
        System.out.println("A_pub = g^a mod p = " + A_pub);
        System.out.println("B_pub = g^b mod p = " + B_pub + "\n");

        long sigA = CryptoUtils.sign(String.valueOf(A_pub), A.getRsaKeyPair());
        long sigB = CryptoUtils.sign(String.valueOf(B_pub), B.getRsaKeyPair());

        System.out.println("Digital signatures created:");
        System.out.println("Alice signs A_pub");
        System.out.println("Bob signs B_pub\n");

        System.out.println("Verifying Alice signature...");
        boolean validA = CryptoUtils.verify(String.valueOf(A_pub), sigA, A.getCertificate().getE(), A.getCertificate().getN());

        System.out.println(validA ? "Alice signature VALID\n" : "Alice signature INVALID\n");

        System.out.println("Verifying Bob signature...");
        boolean validB = CryptoUtils.verify(String.valueOf(B_pub), sigB, B.getCertificate().getE(), B.getCertificate().getN());

        System.out.println(validB ? "Bob signature VALID\n" : "Bob signature INVALID\n");

        if (!validA || !validB) {
            System.out.println("Authentication FAILED!");
            return;
        }

        System.out.println("Computing shared secret...\n");

        long KA = CryptoUtils.modPower(B_pub, a, P);
        long KB = CryptoUtils.modPower(A_pub, b, P);

        System.out.println("Shared key computed successfully:");
        System.out.println("K_A = " + KA);
        System.out.println("K_B = " + KB + "\n");

        System.out.println("*** PROTOCOL SUCCESSFUL ***");
        System.out.println("Secure shared secret established.");
        System.out.println("K = " + KA);
    }
}
