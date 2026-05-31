package cryptosystem;

import cryptosystem.app.AppState;
import cryptosystem.app.DemoIntegrationService;
import cryptosystem.app.IntegrationService;
import cryptosystem.ui.ConsoleMenu;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        AppState state = new AppState();
        IntegrationService integrationService = new DemoIntegrationService();
        ConsoleMenu menu = new ConsoleMenu(new Scanner(System.in), state, integrationService);
        menu.run();
    }
}
