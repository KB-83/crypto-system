package cryptosystem.phase2;

import cryptosystem.phase1.Certificate;

public interface Phase2Service {
    int establishSharedKey(Certificate certificateA, Certificate certificateB);
}
