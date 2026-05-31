package cryptosystem.phase3;

public final class FeistelCipher {
    public static final int ROUNDS = 4;

    private static final int[] S_BOX = {
            12, 5, 6, 11,
            9, 0, 10, 13,
            3, 14, 15, 8,
            4, 7, 1, 2
    };

    private static final int[] PERMUTATION = {0, 4, 2, 6, 1, 5, 3, 7};

    private FeistelCipher() {
    }

    public static int encryptBlock(int block, int masterKey) {
        validateUnsigned16("block", block);
        validateUnsigned16("masterKey", masterKey);

        int left = (block >>> 8) & 0xFF;
        int right = block & 0xFF;
        int[] roundKeys = deriveRoundKeys(masterKey);

        for (int i = 0; i < ROUNDS; i++) {
            int newLeft = right;
            int newRight = (left ^ f(right, roundKeys[i])) & 0xFF;
            left = newLeft;
            right = newRight;
        }

        return ((left << 8) | right) & 0xFFFF;
    }

    public static int decryptBlock(int block, int masterKey) {
        validateUnsigned16("block", block);
        validateUnsigned16("masterKey", masterKey);

        int left = (block >>> 8) & 0xFF;
        int right = block & 0xFF;
        int[] roundKeys = deriveRoundKeys(masterKey);

        for (int i = ROUNDS - 1; i >= 0; i--) {
            int previousRight = left;
            int previousLeft = (right ^ f(left, roundKeys[i])) & 0xFF;
            left = previousLeft;
            right = previousRight;
        }

        return ((left << 8) | right) & 0xFFFF;
    }

    public static int[] deriveRoundKeys(int masterKey) {
        validateUnsigned16("masterKey", masterKey);
        int[] roundKeys = new int[ROUNDS];
        for (int i = 1; i <= ROUNDS; i++) {
            roundKeys[i - 1] = (((masterKey >>> i) ^ (masterKey >>> (i + 4))) & 0xFF);
        }
        return roundKeys;
    }

    public static String roundKeysToString(int masterKey) {
        int[] roundKeys = deriveRoundKeys(masterKey);
        StringBuilder builder = new StringBuilder("[");
        for (int i = 0; i < roundKeys.length; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(roundKeys[i]);
        }
        builder.append("]");
        return builder.toString();
    }

    private static int f(int right, int roundKey) {
        int x = (right ^ roundKey) & 0xFF;
        int high = S_BOX[(x >>> 4) & 0x0F];
        int low = S_BOX[x & 0x0F];
        int substituted = ((high << 4) | low) & 0xFF;
        return permuteByte(substituted);
    }

    private static int permuteByte(int value) {
        int result = 0;
        for (int i = 0; i < PERMUTATION.length; i++) {
            int sourceBit = (value >>> PERMUTATION[i]) & 1;
            result |= sourceBit << i;
        }
        return result & 0xFF;
    }

    private static void validateUnsigned16(String name, int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(name + " must be in range 0..65535");
        }
    }
}
