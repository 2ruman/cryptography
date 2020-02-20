package com.truman.android.kca;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/**
 * Author  : Truman
 * Contact : truman.t.kim@gmail.com
 * Version : 1.0.0
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG_SUFFIX = ".2ruman"; // For grep
    private static final String TAG = "MainActivity" +  TAG_SUFFIX;

    private static final int OP_NONE    = 0;
    private static final int OP_ENCRYPT = 1;
    private static final int OP_DECRYPT = 2;

    private int mLastOp = OP_NONE;

    private Button mBtnEncrypt;
    private Button mBtnDecrypt;
    private Button mBtnRng;
    private Button mBtnHash;
    private EditText mEtPlaintext;
    private EditText mEtCiphertext;
    private EditText mEtMessage;
    private EditText mEtHash;
    private TextView mTvStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.d(TAG, "onCreate()");

        mBtnEncrypt = findViewById(R.id.btn_enc);
        mBtnEncrypt.setOnClickListener(new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                encrypt();
            }
        });
        mBtnDecrypt = findViewById(R.id.btn_dec);
        mBtnDecrypt.setOnClickListener(new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                decrypt();
            }
        });
        mBtnRng = findViewById(R.id.btn_rng);
        mBtnRng.setOnClickListener(new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                rng();
            }
        });
        mBtnHash = findViewById(R.id.btn_hash);
        mBtnHash.setOnClickListener(new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                hash();
            }
        });
        mEtPlaintext = findViewById(R.id.et_pt);
        mEtCiphertext= findViewById(R.id.et_ct);
        mEtCiphertext.setInputType(InputType.TYPE_NULL);
        mEtMessage = findViewById(R.id.et_msg);
        mEtMessage.setInputType(InputType.TYPE_NULL);
        mEtHash= findViewById(R.id.et_hash);
        mEtHash.setInputType(InputType.TYPE_NULL);
        mTvStatus = findViewById(R.id.tv_status);

        mEtPlaintext.setText("Hi, there!");
    }

    private void encrypt() {
        mEtCiphertext.setText("");

        String plainText = mEtPlaintext.getText().toString();
        if (plainText.isEmpty()) {
            updateStatus("Failed due to invalid plain text");
            mLastOp = OP_NONE;
            return;
        }

        byte[] ctBytes = NativeCrypto.encrypt(plainText.getBytes(),
                NativeCrypto.DEFAULT_KEY, NativeCrypto.DEFAULT_IV);
        String cipherText = BytesUtil.bytesToHex(ctBytes);
        mEtPlaintext.setText("");
        mEtCiphertext.setText(cipherText); success();
        mLastOp = OP_ENCRYPT;
        return;
    }

    private void decrypt() {
        mEtPlaintext.setText("");

        if (mLastOp != OP_ENCRYPT) {
            updateStatus("Do encrypt first, before decryption...");
            mLastOp = OP_NONE;
            return;
        }
        String cipherText = mEtCiphertext.getText().toString();
        byte[] ctBytes = null;
        try {
            ctBytes = BytesUtil.hexToBytes(cipherText);
        } catch (Exception e) { e.printStackTrace(); }
        if (ctBytes == null) {
            updateStatus("Failed in hex conversion...");
            mLastOp = OP_NONE;
            return;
        }

        byte[] ptBytes = NativeCrypto.decrypt(ctBytes,
                NativeCrypto.DEFAULT_KEY, NativeCrypto.DEFAULT_IV);
        String plainText = new String(ptBytes);
        mEtCiphertext.setText("");
        mEtPlaintext.setText(plainText); success();
        mLastOp = OP_DECRYPT;
        return;
    }

    private void rng() {
        byte[] randNum = NativeCrypto.generateRandom(32);
        String randNumStr = BytesUtil.bytesToHex(randNum);

        mEtMessage.setText(randNumStr); success();
    }

    private void hash() {
        String msgStr = mEtMessage.getText().toString();
        if (msgStr.isEmpty()) {
            updateStatus("Failed due to empty message...");
            return;
        }

        byte[] msg = null;
        try {
            msg = BytesUtil.hexToBytes(msgStr);
        } catch (Exception e) { e.printStackTrace(); }
        if (msg == null) {
            updateStatus("Failed in hex conversion...");
            return;
        }

        byte[] hashed = NativeCrypto.SHA256(msg);
        String hashedStr =  BytesUtil.bytesToHex(hashed);

        mEtHash.setText(hashedStr); success();
    }

    private void success() {
        updateStatus("Done!");
    }

    private void updateStatus(String status) {
        if (status ==null) {
            status = "null";
        }
        mTvStatus.setText(status);
    }
}