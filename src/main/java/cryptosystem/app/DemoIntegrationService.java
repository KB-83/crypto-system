package cryptosystem.app;

import cryptosystem.phase1.Certificate;
import cryptosystem.phase1.RsaPublicKey;

public class DemoIntegrationService implements IntegrationService {
    private static final int DEMO_MASTER_KEY = 0xBEEF;

    @Override
    public void initializeSystem(AppState state) {
        // This temporary implementation lets the UI and Feistel phase run before Phase 1 is merged.
        state.setCaPublicKey(new RsaPublicKey(3233, 17));
        state.setUserAPublicKey(new RsaPublicKey(2773, 17));
        state.setUserBPublicKey(new RsaPublicKey(3599, 17));
        state.setCertificateA(new Certificate("A", 2773, 17, 142));
        state.setCertificateB(new Certificate("B", 3599, 17, 219));
        state.setCertificatesVerified(true);
        state.setInitialized(true);
        state.clearMasterKey();
        state.setLastEncryptedBlocks(new int[0]);
    }

    @Override
    public int establishSharedKey(AppState state) {
        if (!state.isInitialized()) {
            throw new IllegalStateException("Initialize the system first using option 1.");
        }
        if (!state.areCertificatesVerified()) {
            throw new IllegalStateException("Certificates are not verified.");
        }

        // Replace this value with the real authenticated Diffie-Hellman result from Phase 2.
        state.setMasterKey(DEMO_MASTER_KEY);
        return DEMO_MASTER_KEY;
    }
}
