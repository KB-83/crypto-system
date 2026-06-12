package cryptosystem.phase1;

import java.util.Random;

public class CryptoUtils {

    private static final Random random = new Random();

    public static final int[] PRIMES = {53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
            109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199};

    public static RSAKeyPair generateRSAKeyPair() {

        long p = PRIMES[random.nextInt(PRIMES.length)];
        long q = p;

        while (q == p) {
            q = PRIMES[random.nextInt(PRIMES.length)];
        }

        long n = p * q;

        long phi = (p - 1) * (q - 1);

        long e = 257;

        while (gcd(e, phi) != 1) {
            e += 2;
        }

        long d = modInverse(e, phi);

        return new RSAKeyPair(n, e, d);
    }

    public static long gcd(long a, long b) {
        while (b != 0) {
            long t = a % b;
            a = b;
            b = t;
        }
        return a;
    }

    public static long modPower(long base, long exp, long mod) {

        long result = 1;
        base %= mod;

        while (exp > 0) {

            if ((exp & 1) == 1) { // if the lsb is 1 (exp = odd)
                result = (result * base) % mod;
            }

            base = (base * base) % mod;
            exp >>= 1; // shift the exponent to the right
        }

        return result;
    }

    public static long modInverse(long a, long m) {

        long m0 = m;
        long y = 0;
        long x = 1;

        while (a > 1) {

            long q = a / m;

            long t = m;
            m = a % m;
            a = t;

            t = y;
            y = x - q * y;
            x = t;
        }

        if (x < 0) {
            x += m0;
        }

        return x;
    }


    public static int simpleHash(String data) {

        byte[] bytes = data.getBytes();

        int h = 0;

        for (byte b : bytes)
            h ^= (b & 0xFF);

        return h;
    }

    public static long sign(String data, RSAKeyPair keys) {

        int hash = simpleHash(data);

        return modPower(hash, keys.getD(), keys.getN());
    }

    public static boolean verify(String data, long signature, long e, long n) {

        int expected = simpleHash(data);

        long recovered = modPower(signature, e, n);

        return recovered == expected;
    }
}
