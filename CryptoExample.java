import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        // Generate keys
        KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
        desKeyGen.init(56);  // DES key size
        SecretKey desKey = desKeyGen.generateKey();

        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(128); // AES key size
        SecretKey aesKey = aesKeyGen.generateKey();

        // Example plaintext
        byte[] desPlaintext = "Hello!".getBytes();  // 6 bytes (not aligned)
        byte[] aesPlaintext = "AES Example".getBytes(); // 11 bytes (not aligned)

        // Pad to match block size
        byte[] paddedDES = pad(desPlaintext, 8);
        byte[] paddedAES = pad(aesPlaintext, 16);

        // Encrypt with DES
        Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] desEncrypted = desCipher.doFinal(paddedDES);
        System.out.println("DES Encrypted: " + bytesToHex(desEncrypted));

        // Encrypt with AES
        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] aesEncrypted = aesCipher.doFinal(paddedAES);
        System.out.println("AES Encrypted: " + bytesToHex(aesEncrypted));

        // Decrypt DES
        desCipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] desDecrypted = removePadding(desCipher.doFinal(desEncrypted));
        System.out.println("DES Decrypted: " + new String(desDecrypted));

        // Decrypt AES
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] aesDecrypted = removePadding(aesCipher.doFinal(aesEncrypted));
        System.out.println("AES Decrypted: " + new String(aesDecrypted));
    }

    // PKCS7-like Padding for NoPadding Mode
    public static byte[] pad(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
        return paddedData;
    }

    // Remove Padding
    public static byte[] removePadding(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    // Convert bytes to Hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
