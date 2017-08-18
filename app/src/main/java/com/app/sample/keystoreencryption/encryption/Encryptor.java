package com.app.sample.keystoreencryption.encryption;

import android.util.Base64;

import com.app.sample.keystoreencryption.LogUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * used for encryption for API communication
 */
public class Encryptor implements Encryption {

    private static final String mKey = "dS6AR8FR9wG9mZ9l";
    private static final String mInitVector = "7Q2LqiBlXnPOkwnK";
    private static final java.lang.String PADDING = "AES/CBC/PKCS7Padding";
    private static final String CHARSET = "UTF-8";
    private static final String AES = "AES";

    public String encrypt(String value) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            IvParameterSpec iv = new IvParameterSpec(mInitVector.getBytes(CHARSET));
            SecretKeySpec skeySpec = new SecretKeySpec(mKey.getBytes(CHARSET), AES);
            Cipher cipher = Cipher.getInstance(PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            final String encryptedString = Base64.encodeToString(encrypted, Base64.DEFAULT).trim();
            LogUtils.LOGD(Encryptor.class.getSimpleName(), "encrypted string: " + encryptedString);
            return encryptedString;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encrypted) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            IvParameterSpec iv = new IvParameterSpec(mInitVector.getBytes(CHARSET));
            SecretKeySpec skeySpec = new SecretKeySpec(mKey.getBytes(CHARSET), AES);
            Cipher cipher = Cipher.getInstance(PADDING);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT));
            final String result = new String(original);
            LogUtils.LOGD(Encryptor.class.getSimpleName(), "Decrypted string is :" + result);
            return result;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}