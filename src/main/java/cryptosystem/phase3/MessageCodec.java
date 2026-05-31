package cryptosystem.phase3;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class MessageCodec {
    private MessageCodec() {
    }

    public static int[] encryptMessage(String plainText, int masterKey) {
        byte[] ascii = toAsciiBytes(plainText);
        byte[] padded = Padding7816.apply(ascii);
        int[] plainBlocks = bytesToBlocks(padded);
        int[] encryptedBlocks = new int[plainBlocks.length];

        for (int i = 0; i < plainBlocks.length; i++) {
            encryptedBlocks[i] = FeistelCipher.encryptBlock(plainBlocks[i], masterKey);
        }

        return encryptedBlocks;
    }

    public static String decryptMessage(int[] encryptedBlocks, int masterKey) {
        int[] plainBlocks = new int[encryptedBlocks.length];
        for (int i = 0; i < encryptedBlocks.length; i++) {
            validateUnsigned16("encryptedBlocks[" + i + "]", encryptedBlocks[i]);
            plainBlocks[i] = FeistelCipher.decryptBlock(encryptedBlocks[i], masterKey);
        }

        byte[] padded = blocksToBytes(plainBlocks);
        byte[] plain = Padding7816.remove(padded);
        return new String(plain, StandardCharsets.US_ASCII);
    }

    public static int[] bytesToBlocks(byte[] bytes) {
        if ((bytes.length % 2) != 0) {
            throw new IllegalArgumentException("Byte array length must be even for 16-bit blocks.");
        }

        int[] blocks = new int[bytes.length / 2];
        for (int i = 0; i < blocks.length; i++) {
            int high = bytes[2 * i] & 0xFF;
            int low = bytes[2 * i + 1] & 0xFF;
            blocks[i] = ((high << 8) | low) & 0xFFFF;
        }
        return blocks;
    }

    public static byte[] blocksToBytes(int[] blocks) {
        byte[] bytes = new byte[blocks.length * 2];
        for (int i = 0; i < blocks.length; i++) {
            validateUnsigned16("blocks[" + i + "]", blocks[i]);
            bytes[2 * i] = (byte) ((blocks[i] >>> 8) & 0xFF);
            bytes[2 * i + 1] = (byte) (blocks[i] & 0xFF);
        }
        return bytes;
    }

    public static int[] parseBlocks(String input) {
        String normalized = input.trim().replace("[", "").replace("]", "");
        if (normalized.length() == 0) {
            return new int[0];
        }

        String[] parts = normalized.split(",");
        List<Integer> parsedBlocks = new ArrayList<Integer>();
        for (int i = 0; i < parts.length; i++) {
            String token = parts[i].trim();
            if (token.length() == 0) {
                throw new IllegalArgumentException("Empty block value in input.");
            }
            try {
                int value = Integer.parseInt(token);
                validateUnsigned16("cipher block", value);
                parsedBlocks.add(Integer.valueOf(value));
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid block value: " + token, ex);
            }
        }

        int[] result = new int[parsedBlocks.size()];
        for (int i = 0; i < parsedBlocks.size(); i++) {
            result[i] = parsedBlocks.get(i).intValue();
        }
        return result;
    }

    public static String blocksToCsv(int[] blocks) {
        StringBuilder builder = new StringBuilder("[");
        for (int i = 0; i < blocks.length; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(blocks[i]);
        }
        builder.append("]");
        return builder.toString();
    }

    public static String blocksToBinaryString(int[] blocks) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < blocks.length; i++) {
            if (i > 0) {
                builder.append(" ");
            }
            builder.append(to16BitBinary(blocks[i]));
        }
        return builder.toString();
    }

    private static String to16BitBinary(int value) {
        String binary = Integer.toBinaryString(value & 0xFFFF);
        StringBuilder builder = new StringBuilder();
        for (int i = binary.length(); i < 16; i++) {
            builder.append('0');
        }
        builder.append(binary);
        return builder.toString();
    }

    private static byte[] toAsciiBytes(String input) {
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 127) {
                throw new IllegalArgumentException("Only ASCII messages are supported by the project specification.");
            }
        }
        return input.getBytes(StandardCharsets.US_ASCII);
    }

    private static void validateUnsigned16(String name, int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(name + " must be in range 0..65535");
        }
    }
}
