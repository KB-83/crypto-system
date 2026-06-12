package cryptosystem.phase2;

import cryptosystem.phase1.Certificate;
import cryptosystem.phase1.Phase1ServiceImpl;

public class Phase2ServiceImpl implements Phase2Service {

    private final Phase1ServiceImpl phase1;

    public Phase2ServiceImpl(
            Phase1ServiceImpl phase1) {

        this.phase1 = phase1;
    }

    @Override
    public int establishSharedKey(
            Certificate certificateA,
            Certificate certificateB) {

        return DiffieHellman.generateSharedKey(
                phase1.getUserA(),
                phase1.getUserB(),
                phase1.getCertificateAuthority());
    }
}