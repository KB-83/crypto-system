package cryptosystem.ui;

import cryptosystem.app.AppState;
import cryptosystem.app.IntegrationService;
import cryptosystem.phase3.FeistelCipher;
import cryptosystem.phase3.MessageCodec;

import java.util.OptionalInt;
import java.util.Scanner;

public class ConsoleMenu {
    private final Scanner scanner;
    private final AppState state;
    private final IntegrationService integrationService;

    public ConsoleMenu(Scanner scanner, AppState state, IntegrationService integrationService) {
        this.scanner = scanner;
        this.state = state;
        this.integrationService = integrationService;
    }

    public void run() {
        boolean running = true;
        while (running) {
            showMenu();
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1":
                    initializeSystem();
                    break;
                case "2":
                    establishSharedKey();
                    break;
                case "3":
                    encryptMessage();
                    break;
                case "4":
                    decryptMessage();
                    break;
                case "5":
                    showCurrentStatus();
                    break;
                case "6":
                    System.out.println("Goodbye!");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid choice. Please enter a number from 1 to 6.");
                    break;
            }
            System.out.println();
        }
    }

    private void showMenu() {
        System.out.println("==================================================");
        System.out.println("SECURE CRYPTOGRAPHY SYSTEM");
        System.out.println("==================================================");
        System.out.println("1. Initialize system (generate keys & certificates)");
        System.out.println("2. Establish shared key (DH exchange with authentication)");
        System.out.println("3. Encrypt a message (A -> B)");
        System.out.println("4. Decrypt a message (B)");
        System.out.println("5. Show current status");
        System.out.println("6. Exit");
        System.out.println("==================================================");
        System.out.print("Choice: ");
    }

    private void initializeSystem() {
        integrationService.initializeSystem(state);
        System.out.println("System initialized successfully.");
        System.out.println("CA public key: " + state.getCaPublicKey());
        System.out.println("User A public key: " + state.getUserAPublicKey());
        System.out.println("User B public key: " + state.getUserBPublicKey());
        System.out.println("Certificate A verified: " + state.areCertificatesVerified());
        System.out.println("Certificate B verified: " + state.areCertificatesVerified());
    }

    private void establishSharedKey() {
        try {
            int masterKey = integrationService.establishSharedKey(state);
            System.out.println("Shared key established successfully.");
            System.out.println("master_key = " + masterKey + " (0x" + String.format("%04X", Integer.valueOf(masterKey)) + ")");
            System.out.println("Round keys = " + FeistelCipher.roundKeysToString(masterKey));
        } catch (IllegalStateException ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }

    private void encryptMessage() {
        OptionalInt masterKey = state.getMasterKey();
        if (!masterKey.isPresent()) {
            System.out.println("Error: master_key is not available. Run option 2 first.");
            return;
        }

        System.out.print("Enter ASCII message: ");
        String message = scanner.nextLine();
        try {
            int[] encryptedBlocks = MessageCodec.encryptMessage(message, masterKey.getAsInt());
            state.setLastEncryptedBlocks(encryptedBlocks);
            System.out.println("Encrypted blocks as integers:");
            System.out.println(MessageCodec.blocksToCsv(encryptedBlocks));
            System.out.println("Encrypted blocks as binary:");
            System.out.println(MessageCodec.blocksToBinaryString(encryptedBlocks));
        } catch (IllegalArgumentException ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }

    private void decryptMessage() {
        OptionalInt masterKey = state.getMasterKey();
        if (!masterKey.isPresent()) {
            System.out.println("Error: master_key is not available. Run option 2 first.");
            return;
        }

        System.out.println("Enter encrypted blocks separated by commas.");
        System.out.println("Press Enter to use the last encrypted blocks stored in memory.");
        System.out.print("Blocks: ");
        String input = scanner.nextLine();

        try {
            int[] encryptedBlocks;
            if (input.trim().length() == 0) {
                encryptedBlocks = state.getLastEncryptedBlocks();
                if (encryptedBlocks.length == 0) {
                    System.out.println("Error: no encrypted blocks are stored in memory.");
                    return;
                }
            } else {
                encryptedBlocks = MessageCodec.parseBlocks(input);
            }

            String plainText = MessageCodec.decryptMessage(encryptedBlocks, masterKey.getAsInt());
            System.out.println("Decrypted message:");
            System.out.println(plainText);
        } catch (IllegalArgumentException ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }

    private void showCurrentStatus() {
        System.out.println("Current status");
        System.out.println("--------------");
        System.out.println("Initialized: " + state.isInitialized());
        System.out.println("CA public key: " + valueOrDash(state.getCaPublicKey()));
        System.out.println("User A public key: " + valueOrDash(state.getUserAPublicKey()));
        System.out.println("User B public key: " + valueOrDash(state.getUserBPublicKey()));
        System.out.println("Certificate A: " + valueOrDash(state.getCertificateA()));
        System.out.println("Certificate B: " + valueOrDash(state.getCertificateB()));
        System.out.println("Certificates verified: " + state.areCertificatesVerified());

        if (state.getMasterKey().isPresent()) {
            int key = state.getMasterKey().getAsInt();
            System.out.println("master_key: " + key + " (0x" + String.format("%04X", Integer.valueOf(key)) + ")");
            System.out.println("Round keys: " + FeistelCipher.roundKeysToString(key));
        } else {
            System.out.println("master_key: -");
        }

        int[] lastEncrypted = state.getLastEncryptedBlocks();
        if (lastEncrypted.length == 0) {
            System.out.println("Last encrypted message: -");
        } else {
            System.out.println("Last encrypted message: " + MessageCodec.blocksToCsv(lastEncrypted));
        }
    }

    private String valueOrDash(Object value) {
        return value == null ? "-" : value.toString();
    }
}
