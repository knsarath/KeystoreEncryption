package com.sarath.sample.keystoreencryption;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.sarath.sample.keystoreencryption.encryption.keystore.KeyStoreEncryptionManager;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private Button mButtonEncrypt;
    private EditText mEditText;
    private EditText mResultEditText;
    private KeyStoreEncryptionManager mKeyStoreEncryptionManager;
    private Button mButtonDecrypt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mKeyStoreEncryptionManager = new KeyStoreEncryptionManager(this);
        mButtonEncrypt = (Button) findViewById(R.id.btn_enc);
        mButtonDecrypt = (Button) findViewById(R.id.btn_dec);
        mEditText = (EditText) findViewById(R.id.value);
        mResultEditText = (EditText) findViewById(R.id.result);
        mButtonEncrypt.setOnClickListener(this);
        mButtonDecrypt.setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {

            case R.id.btn_enc:
                String encrypt = mKeyStoreEncryptionManager.encrypt(mEditText.getText().toString());
                mResultEditText.setText(encrypt);
                break;

            case R.id.btn_dec:
                String decrypt = mKeyStoreEncryptionManager.decrypt(mEditText.getText().toString());
                mResultEditText.setText(decrypt);
                break;
        }
    }

    public void clearText(View view) {
        mEditText.setText("");
    }
}
