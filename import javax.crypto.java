import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoLab {
    public static void main(String[] args) throws Exception {
        String plaintext = "Love2Crypt";

        // Generate DES and AES keys
        SecretKey desKey = KeyGenerator.getInstance("DES").generateKey();
        SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();

        // Generate random IVs for CBC mode
        IvParameterSpec desIv = generateIv(8);
        IvParameterSpec aesIv = generateIv(16);

        // Encrypt and print the results
        System.out.println("DES-ECB: " + encrypt(plaintext, desKey, "DES/ECB/PKCS5Padding", null));
        System.out.println("DES-CBC: " + encrypt(plaintext, desKey, "DES/CBC/PKCS5Padding", desIv));
        System.out.println("AES-ECB: " + encrypt(plaintext, aesKey, "AES/ECB/PKCS5Padding", null));
        System.out.println("AES-CBC: " + encrypt(plaintext, aesKey, "AES/CBC/PKCS5Padding", aesIv));

        // File encryption
        String inputFile = "input.txt";
        String encryptedFile = "encrypted.bin";
        String decryptedFile = "decrypted.txt";

        // Create and write input file
        writeToFile(inputFile, "This is a secret message!");

        // Encrypt and store into a file
        encryptFile(inputFile, encryptedFile, desKey, "DES/CBC/PKCS5Padding", desIv);

        // Decrypt back to text
        decryptFile(encryptedFile, decryptedFile, desKey, "DES/CBC/PKCS5Padding", desIv);

        System.out.println("Decryption completed! Check decrypted.txt");
    }

    // Encrypt a string and return base64 encoded string
    public static String encrypt(String plaintext, SecretKey key, String transformation, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        if (iv != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt a string (not used for file operations)
    public static String decrypt(String encryptedText, SecretKey key, String transformation, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        if (iv != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // Encrypt a file
    public static void encryptFile(String inputFile, String outputFile, SecretKey key, String transformation, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            processFile(cipher, fis, fos);
        }
    }

    // Decrypt a file
    public static void decryptFile(String inputFile, String outputFile, SecretKey key, String transformation, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            processFile(cipher, fis, fos);
        }
    }

    // Process file encryption/decryption
    private static void processFile(Cipher cipher, FileInputStream fis, FileOutputStream fos) throws Exception {
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) fos.write(output);
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) fos.write(outputBytes);
    }

    // Generate IV for CBC mode
    private static IvParameterSpec generateIv(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Write a string to a file
    private static void writeToFile(String filename, String data) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(data);
        }
    }
}
