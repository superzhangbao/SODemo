package com.hengsheng.sodemo;

import android.annotation.SuppressLint;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;
@SuppressLint("SetTextI18n")
public class MainActivity extends AppCompatActivity {


    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.sample_text);
        tv.setText(NativeUtils.getKey(this)+"\n"+NativeUtils.getIv(this));
        Log.e(TAG,NativeUtils.getMyName());
    }

    public void getSignInfo() {
        try {
            PackageInfo packageInfo = getPackageManager().getPackageInfo(
                    getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signs = packageInfo.signatures;
            Signature sign = signs[0];
            System.out.println(sign.toCharsString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
