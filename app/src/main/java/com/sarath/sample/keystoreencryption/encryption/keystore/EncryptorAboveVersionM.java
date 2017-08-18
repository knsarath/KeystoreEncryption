package com.sarath.sample.keystoreencryption.encryption.keystore;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;


import com.sarath.sample.keystoreencryption.LogUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.x500.X500Principal;

import static com.sarath.sample.keystoreencryption.encryption.keystore.KeyStoreEncryptionManager.ALIAS;
import static com.sarath.sample.keystoreencryption.encryption.keystore.KeyStoreEncryptionManager.KEYSTORE_PROVIDER;


/**
 * Created by sarath on 15/5/17.
 */

/**
 * Keystore encryptor class which is for android versions equal and above M (Marshmallow api 23+)
 */
class EncryptorAboveVersionM implements KeyStoreEncryptor {

    private static final String FIXED_IV = "Huv7ppXK8wLn";
    private KeyStore mKeyStore;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_BIT_LENGTH = 256;
    private static final int GCM_TAG_LENGTH = 128;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void init() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, NoSuchProviderException {
        mKeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        mKeyStore.load(null);
        if (!mKeyStore.containsAlias(ALIAS)) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);
            KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setCertificateSubject(new X500Principal("CN = " + ALIAS))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setKeySize(AES_BIT_LENGTH)
                    .setKeyValidityEnd(end.getTime())
                    .setKeyValidityStart(start.getTime())
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false)
                    .build();
            keyGen.init(spec);
            keyGen.generateKey();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public String encrypt(String plainText) throws UnrecoverableEntryException, NoSuchPaddingException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, NoSuchProviderException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        LogUtils.LOGD(KeyStoreEncryptionManager.TAG, this.getClass().getSimpleName() + ": encrypt()");
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, FIXED_IV.getBytes()));
        byte[] encodedBytes = c.doFinal(plainText.getBytes());
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public String decrypt(String cipherText) throws UnrecoverableEntryException, NoSuchPaddingException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, NoSuchProviderException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        LogUtils.LOGD(KeyStoreEncryptionManager.TAG, this.getClass().getSimpleName() + ": decrypt()");
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, FIXED_IV.getBytes()));
        byte[] decodedBytes = c.doFinal(Base64.decode(cipherText, Base64.DEFAULT));
        return new String(decodedBytes);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Key getSecretKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, NoSuchProviderException, UnrecoverableEntryException {
        Key key = null;
        if (mKeyStore.containsAlias(ALIAS) && mKeyStore.entryInstanceOf(ALIAS, KeyStore.SecretKeyEntry.class)) {
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) mKeyStore.getEntry(ALIAS, null);
            key = entry.getSecretKey();
        }
        return key;
    }
}
