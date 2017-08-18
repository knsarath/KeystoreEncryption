package com.app.sample.keystoreencryption.encryption;

/**
 * Created by sarath on 16/5/17.
 */

public interface Encryption {
    String encrypt(String plainText);

    String decrypt(String cipherText);
}
