package enc.dec.encryp_decryp;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SymmetricEncryption {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private static SecretKeySpec generateKey(String secret) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = sha.digest(secret.getBytes());
        key = Arrays.copyOf(key, 16);
        return new SecretKeySpec(key, "AES");
    }

    public static String encrypt(String input, String secret) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec key = generateKey(secret);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        byte[] ciphertext = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ciphertext, 0, iv.length);
        System.arraycopy(encrypted, 0, ciphertext, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decrypt(String ciphertext, String secret) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec key = generateKey(secret);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        byte[] iv = Arrays.copyOfRange(ciphertextBytes, 0, cipher.getBlockSize());
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        byte[] encrypted = Arrays.copyOfRange(ciphertextBytes, cipher.getBlockSize(), ciphertextBytes.length);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);

    }

    public static void main(String[] args) throws Exception{
        String secretWord = "secretTest";
        String wordToEncDec = "test text";
        String encrypted = encrypt(wordToEncDec, secretWord);
        String decrypted = decrypt(encrypted, secretWord);
        System.out.println("Word to be encrypted and decrypted: " + wordToEncDec);
        System.out.println("encrypted: " + encrypted);
        System.out.println("decrypted: " + decrypted);
    }
}
