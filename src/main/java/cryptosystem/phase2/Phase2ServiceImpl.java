package cryptosystem.phase2;

import cryptosystem.phase1.*;

import java.util.Random;

public class Phase2ServiceImpl implements Phase2Service {

    private static final long P = 65521;
    private static final long G = 11;

    private final Phase1ServiceImpl phase1;

    public Phase2ServiceImpl(Phase1ServiceImpl phase1) {
        this.phase1 = phase1;
    }

    @Override
    public int establishSharedKey(
            Certificate certificateA,
            Certificate certificateB) {

        User userA = phase1.getUserA();
        User userB = phase1.getUserB();

        Random random = new Random();

        long a = 2 + random.nextInt(50000);
        long b = 2 + random.nextInt(50000);

        long x = CryptoUtils.modPower(G, a, P);
        long y = CryptoUtils.modPower(G, b, P);

        long sigX =
                CryptoUtils.sign(
                        String.valueOf(x),
                        userA.getRsaKeyPair());

        long sigY =
                CryptoUtils.sign(
                        String.valueOf(y),
                        userB.getRsaKeyPair());

        boolean validA =
                CryptoUtils.verify(
                        String.valueOf(x),
                        sigX,
                        certificateA.getE(),
                        certificateA.getN());

        boolean validB =
                CryptoUtils.verify(
                        String.valueOf(y),
                        sigY,
                        certificateB.getE(),
                        certificateB.getN());

        if (!validA || !validB) {
            throw new IllegalStateException(
                    "DH authentication failed");
        }

        long sharedA =
                CryptoUtils.modPower(y, a, P);

        long sharedB =
                CryptoUtils.modPower(x, b, P);

        if (sharedA != sharedB) {
            throw new IllegalStateException(
                    "Shared key mismatch");
        }

        return (int) (sharedA % 65536);
    }
}