package net.boillod.aes;

import org.fest.assertions.api.Assertions;
import org.junit.Before;
import org.junit.Test;

public class AesHelperTest {

    // Encryption parameters
    private static final String PASSPHRASE = "random pass phrase";
    private static final String SALT = "72216a6607a2a2d8939d5a324b195ba32bab81cd";
    private static final String IV = "91a90d6aa4241465fb2ac9ab0e06eba0";

    // Test values
    private static final String PLAIN_TEXT = "My message in plain text";
    private static final String ENCRYPTED_TEXT = "BkcWfejPOMwRObflM2Dn6F2vFAP8D8Z7yUbsI4YIfB0=";

    private AesHelper aesHelper;

    @Before
    public void setUp() {
        aesHelper = new AesHelper(PASSPHRASE, SALT, IV);
    }

    @Test
    public void encrypt() {
        String encrypt = aesHelper.encrypt(PLAIN_TEXT);
        Assertions.assertThat(encrypt).isEqualTo(ENCRYPTED_TEXT);
    }

    @Test
    public void decrypt() {
        String decrypt = aesHelper.decrypt(ENCRYPTED_TEXT);
        Assertions.assertThat(decrypt).isEqualTo(PLAIN_TEXT);
    }

}