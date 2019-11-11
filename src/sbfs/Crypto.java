/*
 * Crypto : necessary functions to ensure proper file encryption and decryption
 * Author: Sébastien Maes
 */
package sbfs;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Crypto {

    /**
     * Generate a private and a public key (RSA).
     * @param path Path to Directory that will contain keys
     */
    public static void generateKeyPair(String path, int keySize) throws NoSuchAlgorithmException, IOException {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            Files.createDirectories(Paths.get(path));
            Utilities.writeFile(kp.getPrivate().getEncoded(), path + "/private.key");
            Utilities.writeFile(kp.getPublic().getEncoded(), path + "/public.key");
    }

    /**
     * Load a private and a public key from a directory (RSA).
     * @param path Path to Directory that contains keys
     * @return keypair
     */
    public static KeyPair loadKeyPair(String path) throws NoSuchAlgorithmException, IOException,
            InvalidKeySpecException {
        // Read public and private key
        byte[] encodedPublicKey = Files.readAllBytes(Paths.get(path + "/public.key"));
        byte[] encodedPrivateKey = Files.readAllBytes(Paths.get(path + "/private.key"));
        // Generate KeyPair
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        PrivateKey sk = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));

        return new KeyPair(pk, sk);
    }

    /**
     * Generate an AES-256 secret key.
     * @return secretkey
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * Encrypt an AES secret key with a RSA public key.
     * @param skToEncrypt The secret key to encrypt
     * @param publicKey RSA public key
     * @return encrypted secret key byte array
     */
    public static byte[] encryptSecretKey(SecretKey skToEncrypt, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(skToEncrypt);
    }

    /**
     * Decrypt an AES secret key with a RSA private key.
     * @param encryptedKey The secret key to decrypt
     * @param privateKey RSA private key
     * @return decrypted secret key
     */
    public static SecretKey decryptSecretKey(byte[] encryptedKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
    InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
    }

    /**
     * Encrypt a file using an AES secret key.
     * @param file The file to encrypt
     * @param sk AES Secret key
     */
    public static void encryptFile(File file, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // Generate IV
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom srand = new SecureRandom();
        srand.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, sk, ivSpec);

        // Get file path for encrypted version
        String encFilePath = Utilities.getEncryptedFilePath(file);

        // Write IV at the beginning of the (empty) encrypted file
        Utilities.writeFile(iv,encFilePath);

        // Read from source file and append ciphered data to destination file
        FileInputStream fis = new FileInputStream(file);
        CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(encFilePath, true), cipher);
        int charRead;
        while((charRead = fis.read()) != -1){
            cos.write(charRead);
        }
        cos.close();
        fis.close();
    }

    /**
     * Add an encrypted AES secret key at the beginning of a file
     * @param file File
     * @param encryptedKey encrypted AES key
     */
    public static void addKeyToFile(File file, byte[] encryptedKey) throws IOException {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        byte[] byteArray = new byte[encryptedKey.length + fileBytes.length];
        ByteBuffer bb = ByteBuffer.wrap(byteArray);
        bb.put(encryptedKey).put(fileBytes);
        Utilities.writeFile(bb.array(), file.getPath());
    }

    /**
     * Decrypt a file using an RSA private key.
     * @param file The file to decrypt
     * @param privateKey RSA private key
     */
    public static void decryptFile(File file, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException{
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        ByteBuffer bb = ByteBuffer.wrap(fileBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Get symmetric key
        byte[] encryptedKey = new byte[256];
        bb = bb.get(encryptedKey);

        // Get IV
        byte[] iv = new byte[cipher.getBlockSize()];
        bb = bb.get(iv);

        // Get useful file data
        byte[] fileData = new byte[bb.remaining()];
        bb = bb.get(fileData);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, decryptSecretKey(encryptedKey, privateKey), ivSpec);
        byte[] decryptedData = cipher.doFinal(fileData);

        // Get file path for decrypted version
        String decFilePath = Utilities.getDecryptedFilePath(file);

        // Write decrypted file
        FileOutputStream fos = new FileOutputStream(decFilePath);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        osw.write(new String(decryptedData));
        osw.close();
    }
}
