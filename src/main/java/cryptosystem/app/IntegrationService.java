package cryptosystem.app;

public interface IntegrationService {
    void initializeSystem(AppState state);

    int establishSharedKey(AppState state);
}
