import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;

public class AesBruteForce {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== AES Brute-force Framework ===");
        System.out.print("Enter Base64-encoded ciphertext: ");
        String b64 = scanner.nextLine().trim();

        byte[] cipherText = Base64.getDecoder().decode(b64);

        System.out.println("\nSelect key generation strategy:");
        System.out.println("[1] Wordlist");
        System.out.println("[2] Numeric (0-9999)");
        System.out.println("[3] Random Keys (100 tries)");
        System.out.println("[4] Pattern-based Keys");
        System.out.println("[5] Charset Brute-force (length <= 3)");
        System.out.print("Choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // consume newline

        List<byte[]> keys = switch (choice) {
            case 1 -> loadKeysFromFile("keys.txt");
            case 2 -> generateNumericKeys(0, 9999);
            case 3 -> generateRandomKeys(100);
            case 4 -> generatePatternKeys();
            case 5 -> generateCharsetBruteForce(3);
            default -> throw new IllegalArgumentException("Invalid choice.");
        };

        for (byte[] key : keys) {
            String result = tryDecrypt(cipherText, key);
            if (result != null) {
                System.out.println("\n[+] Key Found: " + new String(key).replace("\0", ""));
                System.out.println("[+] Decrypted: " + result);
                return;
            }
        }

        System.out.println("\n[-] Failed to decrypt with provided keys.");
    }

    public static List<byte[]> loadKeysFromFile(String filename) throws IOException {
        List<byte[]> keys = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = reader.readLine()) != null) {
            keys.add(padKey(line));
        }
        reader.close();
        return keys;
    }

    public static List<byte[]> generateNumericKeys(int start, int end) {
        List<byte[]> keys = new ArrayList<>();
        for (int i = start; i <= end; i++) {
            String num = String.format("%016d", i);
            keys.add(num.getBytes(StandardCharsets.UTF_8));
        }
        return keys;
    }

    public static List<byte[]> generateRandomKeys(int count) {
        List<byte[]> keys = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < count; i++) {
            byte[] key = new byte[16];
            random.nextBytes(key);
            keys.add(key);
        }
        return keys;
    }

    public static List<byte[]> generatePatternKeys() {
        String[] prefixes = {"admin", "user", "test"};
        String[] suffixes = {"123", "2024", "pass"};
        List<byte[]> keys = new ArrayList<>();
        for (String pre : prefixes) {
            for (String suf : suffixes) {
                keys.add(padKey(pre + suf));
            }
        }
        return keys;
    }

    public static List<byte[]> generateCharsetBruteForce(int maxLen) {
        List<byte[]> keys = new ArrayList<>();
        char[] charset = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        brute("", charset, maxLen, keys);
        return keys;
    }

    private static void brute(String prefix, char[] charset, int maxLen, List<byte[]> keys) {
        if (prefix.length() > 0) {
            keys.add(padKey(prefix));
        }
        if (prefix.length() == maxLen) return;
        for (char c : charset) {
            brute(prefix + c, charset, maxLen, keys);
        }
    }

    public static byte[] padKey(String key) {
        byte[] bytes = new byte[16];
        byte[] input = key.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(input, 0, bytes, 0, Math.min(input.length, 16));
        return bytes;
    }

    public static String tryDecrypt(byte[] ciphertext, byte[] key) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            if (isPrintableAscii(result)) {
                return result;
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static boolean isPrintableAscii(String str) {
        for (char c : str.toCharArray()) {
            if (c < 32 || c > 126) return false;
        }
        return true;
    }
}
