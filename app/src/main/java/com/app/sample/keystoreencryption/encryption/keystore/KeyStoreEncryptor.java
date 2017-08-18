package com.app.sample.keystoreencryption.encryption.keystore;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by sarath on 15/5/17.
 */

public interface KeyStoreEncryptor  {
    void init() throws Exception;

    String encrypt(String plainText) throws UnrecoverableEntryException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException;

    String decrypt(String cipherText) throws UnrecoverableEntryException, NoSuchPaddingException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, NoSuchProviderException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;
}
