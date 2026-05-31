package cryptosystem.phase3;

import java.util.Arrays;

public final class Padding7816 {
    private Padding7816() {
    }

    public static byte[] apply(byte[] data) {
        int originalLength = data.length;
        int withMandatoryByte = originalLength + 1;
        int paddedLength = withMandatoryByte;

        while ((paddedLength % 2) != 0) {
            paddedLength++;
        }

        byte[] result = Arrays.copyOf(data, paddedLength);
        result[originalLength] = (byte) 0x80;
        return result;
    }

    public static byte[] remove(byte[] paddedData) {
        int index = paddedData.length - 1;
        while (index >= 0 && paddedData[index] == 0) {
            index--;
        }

        if (index < 0 || (paddedData[index] & 0xFF) != 0x80) {
            throw new IllegalArgumentException("Invalid ISO/IEC 7816-4 padding.");
        }

        return Arrays.copyOf(paddedData, index);
    }
}
