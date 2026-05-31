package cryptosystem.app;

import cryptosystem.phase1.Certificate;
import cryptosystem.phase1.RsaPublicKey;

import java.util.Arrays;
import java.util.OptionalInt;

public class AppState {
    private boolean initialized;
    private boolean certificatesVerified;
    private RsaPublicKey caPublicKey;
    private RsaPublicKey userAPublicKey;
    private RsaPublicKey userBPublicKey;
    private Certificate certificateA;
    private Certificate certificateB;
    private OptionalInt masterKey;
    private int[] lastEncryptedBlocks;

    public AppState() {
        this.initialized = false;
        this.certificatesVerified = false;
        this.masterKey = OptionalInt.empty();
        this.lastEncryptedBlocks = new int[0];
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    public boolean areCertificatesVerified() {
        return certificatesVerified;
    }

    public void setCertificatesVerified(boolean certificatesVerified) {
        this.certificatesVerified = certificatesVerified;
    }

    public RsaPublicKey getCaPublicKey() {
        return caPublicKey;
    }

    public void setCaPublicKey(RsaPublicKey caPublicKey) {
        this.caPublicKey = caPublicKey;
    }

    public RsaPublicKey getUserAPublicKey() {
        return userAPublicKey;
    }

    public void setUserAPublicKey(RsaPublicKey userAPublicKey) {
        this.userAPublicKey = userAPublicKey;
    }

    public RsaPublicKey getUserBPublicKey() {
        return userBPublicKey;
    }

    public void setUserBPublicKey(RsaPublicKey userBPublicKey) {
        this.userBPublicKey = userBPublicKey;
    }

    public Certificate getCertificateA() {
        return certificateA;
    }

    public void setCertificateA(Certificate certificateA) {
        this.certificateA = certificateA;
    }

    public Certificate getCertificateB() {
        return certificateB;
    }

    public void setCertificateB(Certificate certificateB) {
        this.certificateB = certificateB;
    }

    public OptionalInt getMasterKey() {
        return masterKey;
    }

    public void setMasterKey(int masterKey) {
        this.masterKey = OptionalInt.of(masterKey & 0xFFFF);
    }

    public void clearMasterKey() {
        this.masterKey = OptionalInt.empty();
    }

    public int[] getLastEncryptedBlocks() {
        return Arrays.copyOf(lastEncryptedBlocks, lastEncryptedBlocks.length);
    }

    public void setLastEncryptedBlocks(int[] lastEncryptedBlocks) {
        if (lastEncryptedBlocks == null) {
            this.lastEncryptedBlocks = new int[0];
        } else {
            this.lastEncryptedBlocks = Arrays.copyOf(lastEncryptedBlocks, lastEncryptedBlocks.length);
        }
    }
}
