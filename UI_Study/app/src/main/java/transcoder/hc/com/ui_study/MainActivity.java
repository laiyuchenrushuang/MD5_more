package transcoder.hc.com.ui_study;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;


//import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import transcoder.hc.com.ui_study.base.Base64Decoder;


public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    public static String TAG = "lylog";
    Button bt_md5;
    Button bt_aes;
    Button bt_rsa;
    EditText textString;
    TextView textResult;
    Button bt_md5_jie;
    Button bt_aes_jie;
    Button bt_rsa_jie;
    TextView textResult_jie;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);//remove notification bar  即全屏
        initView();
        bindEvent();
    }

    private void bindEvent() {
        bt_md5.setOnClickListener(this);
        bt_aes.setOnClickListener(this);
        bt_rsa.setOnClickListener(this);

        bt_md5_jie.setOnClickListener(this);
        bt_aes_jie.setOnClickListener(this);
        bt_rsa_jie.setOnClickListener(this);
    }

    private void initView() {
        bt_md5 = findViewById(R.id.md5);
        bt_aes = findViewById(R.id.aes);
        bt_rsa = findViewById(R.id.rsa);

        bt_md5_jie = findViewById(R.id.md5_jie);
        bt_aes_jie = findViewById(R.id.aes_jie);
        bt_rsa_jie = findViewById(R.id.rsa_jie);

        textString = findViewById(R.id.text_oringin);
        textResult = findViewById(R.id.text_result);
        textResult_jie = findViewById(R.id.text_result_jie);
    }

    @Override
    public void onClick(View v) {
        String orin = textString.getText().toString();

        KeyPair keyPair = RSAUtils.generateRSAKeyPair(RSAUtils.DEFAULT_KEY_SIZE);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        byte[] encryptBytes = new byte[0];
        String secretKey = AESUtils.generateKey();
        String encryStraes = AESUtils.encrypt(secretKey, orin);

        try {
            encryptBytes = RSAUtils.encryptByPublicKeyForSpilt(orin.getBytes(), publicKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String encryStr = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
        switch (v.getId()) {
            case R.id.md5:
                if (orin != null) {
                    textResult.setText("md5 :" + MD5Utils.getMD5Code(orin) + "\n" + "加密后：" + (MD5Utils.convertMD5(MD5Utils.getMD5Code(orin))));
                    Log.d(TAG, "onClick: textResult =" + textResult.getText().toString());
                }
                break;
            case R.id.aes:

                Log.d(TAG, "onClick: encryStraes =" + encryStraes + "  secretKey" + secretKey);
                textResult.setText(encryStraes);

                break;
            case R.id.rsa:
                try {
                    //公钥加密

                    System.out.println("私钥:" + privateKey);
                    System.out.println("公钥:" + publicKey);
                    Log.d(TAG, "onClick: encryStr =" + encryStr);
                    textResult.setText(encryStr);

                } catch (Exception e) {
                    e.printStackTrace();
                }

                break;


            case R.id.md5_jie:
                if (orin != null) {
                    textResult_jie.setText(MD5Utils.convertMD5(MD5Utils.convertMD5(MD5Utils.getMD5Code(orin))));
                }
                break;
            case R.id.aes_jie:
                String decryStraes = AESUtils.decrypt(secretKey, encryStraes);
                textResult_jie.setText(decryStraes);
                break;
            case R.id.rsa_jie:
                //私钥解密
                try {
                    byte[] decryptBytes = RSAUtils.decryptByPrivateKeyForSpilt(Base64Decoder.decodeToBytes(encryStr), privateKey.getEncoded());
                    String decryStr = new String(decryptBytes);
                    textResult_jie.setText(decryStr);
                } catch (Exception e) {
                    Log.d(TAG, "onClick: error");
                    e.printStackTrace();
                }
                Log.d(TAG, "bijiao: =?\n" + encryStr + "\n" + textResult.getText().toString());
                break;
        }
    }
}
