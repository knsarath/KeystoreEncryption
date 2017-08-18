package com.app.sample.keystoreencryption.encryption.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;


import com.app.sample.keystoreencryption.LogUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static com.app.sample.keystoreencryption.encryption.keystore.KeyStoreEncryptionManager.ALIAS;
import static com.app.sample.keystoreencryption.encryption.keystore.KeyStoreEncryptionManager.KEYSTORE_PROVIDER;


/**
 * Created by sarath on 15/5/17.
 */

/**
 * * Keystore encryptor class which is for android versions below M (Marshmallow)
 */
class EncryptorBelowVersionM implements KeyStoreEncryptor {

    private static final String SHARED_PREFENCE_NAME = "sec_enc_store";
    private static final String ENCRYPTED_KEY = "enc_below_m";
    private static final String ALGORITHM = "RSA";
    private static String RSA_PROVIDER = "AndroidOpenSSL";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String AES_MODE = "AES/ECB/PKCS7Padding";
    private KeyStore mKeyStore;
    private Context mContext;

    public EncryptorBelowVersionM(Context context) {
        mContext = context;
    }


    @Override
    public void init() throws Exception {
        mKeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        mKeyStore.load(null);
        if (!mKeyStore.containsAlias(ALIAS)) {
            // Generate a key pair for encryption
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 30);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                    .setAlias(ALIAS)
                    .setSubject(new X500Principal("CN=" + ALIAS))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, KEYSTORE_PROVIDER);
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }
        GenerateandStoreAESKey();
    }

    public void GenerateandStoreAESKey() throws Exception {
        SharedPreferences pref = mContext.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
        if (enryptedKeyB64 == null) {
            byte[] key = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            byte[] encryptedKey = rsaEncrypt(key);
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
            SharedPreferences.Editor edit = pref.edit();
            edit.putString(ENCRYPTED_KEY, enryptedKeyB64);
            edit.commit();
        }
    }

    private byte[] rsaEncrypt(byte[] secret) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(ALIAS, null);
        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, RSA_PROVIDER);
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();
        byte[] vals = outputStream.toByteArray();
        return vals;
    }

    private byte[] rsaDecrypt(byte[] encrypted) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(ALIAS, null);
        Cipher output = Cipher.getInstance(RSA_MODE, RSA_PROVIDER);
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }
        return bytes;
    }

    private Key getSecretKey(Context context) throws Exception {
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
        // need to check null, omitted here
        byte[] encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT);
        byte[] key = rsaDecrypt(encryptedKey);
        return new SecretKeySpec(key, "AES");
    }

    @Override
    public String encrypt(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, UnrecoverableEntryException, KeyStoreException, IOException, BadPaddingException, IllegalBlockSizeException {
        LogUtils.LOGD(KeyStoreEncryptionManager.TAG, this.getClass().getSimpleName() + ": encrypt()");
        Cipher c = Cipher.getInstance(AES_MODE, "BC");
        try {
            c.init(Cipher.ENCRYPT_MODE, getSecretKey(mContext));
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] encodedBytes = c.doFinal(plainText.getBytes());
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }

    @Override
    public String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        LogUtils.LOGD(KeyStoreEncryptionManager.TAG, this.getClass().getSimpleName() + ": decrypt()");
        Cipher c = Cipher.getInstance(AES_MODE, "BC");
        try {
            c.init(Cipher.DECRYPT_MODE, getSecretKey(mContext));
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] decodedBytes = c.doFinal(Base64.decode(cipherText, Base64.DEFAULT));
        return new String(decodedBytes);
    }
}
