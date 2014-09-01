package net.boillod.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.KeySpec;

/**
 * Utility class for encrypt or decrypt with AES encryption.
 *
 * @see #encrypt(String)
 * @see #decrypt(String)
 */
public class AesHelper {

    private static final int DEFAULT_KEY_SIZE = 128;
    private static final int DEFAULT_ITERATION_COUNT = 7;

    private final Key key;
    private final IvParameterSpec ivParameterSpec;

    /**
     * Initialize an instance of AesHelper with given encryption parameters
     * @param passphrase The passphrase
     * @param salt A hexadecimal String with an even number of characters
     * @param iv Initialization vector. A hexadecimal String of 16 bytes length (i.e 32 characters length)
     */
    public AesHelper(String passphrase, String salt, String iv) {
        this(passphrase, salt, iv, DEFAULT_KEY_SIZE, DEFAULT_ITERATION_COUNT);
    }

    /**
     * Initialize an instance of AesHelper with given encryption parameters
     * @param passphrase The passphrase
     * @param salt A hexadecimal String with an even number of characters
     * @param iv Initialization vector. A hexadecimal String of 16 bytes length (i.e 32 characters length)
     * @param keySize Size of AES key (128, 196, 256).
     * @param iterationCount Iteration count used for key generation.
     */
    public AesHelper(String passphrase, String salt, String iv, int keySize, int iterationCount) {
        this.key = generateKey(passphrase, salt, keySize, iterationCount);
        this.ivParameterSpec = new IvParameterSpec(hex(iv));
    }

    private SecretKey generateKey(String passphrase, String salt, int keySize, int iterationCount) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypt text with AES encryption
     * @param plaintext text to encrypt
     */
    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.key, this.ivParameterSpec);
            byte[] encrypted =  cipher.doFinal(plaintext.getBytes("UTF-8"));
            return base64(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt text with AES encryption
     * @param ciphertext encrypted text
     */
    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.key, this.ivParameterSpec);
            byte[] decrypted = cipher.doFinal(base64(ciphertext));
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    private static byte[] base64(String str) {
        return Base64.decodeBase64(str);
    }

    private static byte[] hex(String str) {
        try {
            return Hex.decodeHex(str.toCharArray());
        }
        catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }
}