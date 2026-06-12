package cryptosystem.app;

import cryptosystem.phase1.*;
import cryptosystem.phase2.*;

public class DemoIntegrationService implements IntegrationService {

    private final Phase1ServiceImpl phase1 =
            new Phase1ServiceImpl();

    private final Phase2ServiceImpl phase2 =
            new Phase2ServiceImpl(phase1);

    @Override
    public void initializeSystem(AppState state) {

        state.setCaPublicKey(
                phase1.getCaPublicKey());

        state.setUserAPublicKey(
                phase1.getUserAPublicKey());

        state.setUserBPublicKey(
                phase1.getUserBPublicKey());

        Certificate certA =
                phase1.issueCertificate(
                        "A",
                        phase1.getUserAPublicKey());

        Certificate certB =
                phase1.issueCertificate(
                        "B",
                        phase1.getUserBPublicKey());

        state.setCertificateA(certA);
        state.setCertificateB(certB);

        boolean okA =
                phase1.verifyCertificate(
                        certA,
                        state.getCaPublicKey());

        boolean okB =
                phase1.verifyCertificate(
                        certB,
                        state.getCaPublicKey());

        state.setCertificatesVerified(okA && okB);

        state.setInitialized(true);

        state.clearMasterKey();
        state.setLastEncryptedBlocks(new int[0]);
    }

    @Override
    public int establishSharedKey(AppState state) {

        if (!state.isInitialized()) {
            throw new IllegalStateException(
                    "Initialize the system first using option 1.");
        }

        if (!state.areCertificatesVerified()) {
            throw new IllegalStateException(
                    "Certificates are not verified.");
        }

        int masterKey =
                phase2.establishSharedKey(
                        state.getCertificateA(),
                        state.getCertificateB());

        state.setMasterKey(masterKey);

        return masterKey;
    }
}