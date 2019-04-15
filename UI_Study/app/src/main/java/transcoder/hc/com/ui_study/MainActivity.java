package transcoder.hc.com.ui_study;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

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
        switch (v.getId()) {
            case R.id.md5:
            if (orin != null) {
                textResult.setText("md5 :"+AppStringHelper.getMD5Code(orin)+"\n"+"laiyu"+(AppStringHelper.convertMD5(AppStringHelper.getMD5Code(orin))));
                Log.d(TAG, "onClick: textResult ="+textResult.getText().toString());
            }
                break;
            case R.id.aes:
                break;
            case R.id.rsa:
                break;


            case R.id.md5_jie:
                if (orin != null) {
                    textResult_jie.setText(AppStringHelper.convertMD5(textResult.getText().toString().substring(textResult.getText().toString().indexOf("laiyu")+1)));
                }
                break;
            case R.id.aes_jie:
                break;
            case R.id.rsa_jie:
                break;
        }
    }
}
