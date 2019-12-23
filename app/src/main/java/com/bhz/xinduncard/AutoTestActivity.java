package com.bhz.xinduncard;

import android.Manifest;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.csizg.securitymt2.SafetyCardMT2;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class AutoTestActivity  extends AppCompatActivity implements View.OnClickListener {

    protected static final String TAG = "AutoTestActivity";
    private TextView mRet;
    private Handler handler = new Handler();

    private static SafetyCardMT2 mSafetyCardMT2;
    private String conn1PubKey = "";//i == 24
    private String conn2PubKey = "";//i == 25
    private String conn3PubKey = "";//i == 26
    private String conn4PubKey = "";//i == 27 len494
    private String conn4PubKey_1 = "";//i == 28 len22

    private String SM2_Cipher = "";
    private String RSA1024_PKCS1_PADDING_Cipher = "";
    private String RSA1024_NO_PADDING_Cipher = "";
    private String RSA2048_PKCS1_PADDING_Cipher = "";
    private String RSA2048_PKCS1_PADDING_Cipher_1 = "";
    private String RSA2048_PKCS1_PADDING_Cipher_2 = "";
    private String RSA2048_NO_PADDING_Cipher = "";
    private String RSA2048_NO_PADDING_Cipher_1 = "";
    private String RSA2048_NO_PADDING_Cipher_2 = "";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auto_test);
        findViewById(R.id.open).setOnClickListener(this);
        findViewById(R.id.start).setOnClickListener(this);
        mRet = (TextView) findViewById(R.id.result);


        // 申请通用权限
        if (Build.VERSION.SDK_INT >= 23) {
            String[] permissions = requestPermissions();
            if (permissions != null) {
                requestPermissions(permissions, 1003);
                return;
            }
        }
        mSafetyCardMT2 = new SafetyCardMT2(this);
    }

    /**
     * 请求需要的权限
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    private String[] requestPermissions() {
        String[] permissions = null;
        List<String> permissionsList = new ArrayList<>();
        addPermission(permissionsList, Manifest.permission.READ_SMS);
        addPermission(permissionsList, Manifest.permission.SEND_SMS);
        addPermission(permissionsList, Manifest.permission.RECEIVE_SMS);
        addPermission(permissionsList, Manifest.permission.WRITE_CONTACTS);
        addPermission(permissionsList, Manifest.permission.READ_CONTACTS);
        addPermission(permissionsList, Manifest.permission.READ_PHONE_STATE);
        addPermission(permissionsList, Manifest.permission.WRITE_EXTERNAL_STORAGE);
        addPermission(permissionsList, Manifest.permission.READ_EXTERNAL_STORAGE);
//    <uses-permission android:name="android.permission.WRITE_SMS"/>
//    <uses-permission android:name="org.simalliance.openmobileapi.SMARTCARD" />
//    <uses-permission android:name="org.simalliance.openmobileapi.BIND_TERMINAL" />
        if (permissionsList.size() > 0) {
            permissions = new String[permissionsList.size()];
            for (int i = 0; i < permissionsList.size(); i++) {
                permissions[i] = permissionsList.get(i);
            }
        }
        return permissions;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void addPermission(List<String> permissionsList, String permission) {
        if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
            permissionsList.add(permission);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 1003) {
            for (int i = 0; i < grantResults.length; i++) {
                int grant = grantResults[i];
                if (grant != PackageManager.PERMISSION_GRANTED) {
                    Toast.makeText(this, "权限未被允许，请手动开启", Toast.LENGTH_LONG).show();
                    return;
                }
            }
            mSafetyCardMT2 = new SafetyCardMT2(this);
//            mSafetyCard.setPrintLog(true);
//            mUCard=new UCard(this,cb1Flag,cb2Flag,cb3Flag,cb4Flag);
//            mUcardAPI=new UcardAPI(this);
        }
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.open:
                beginTime();
                openChannel();
                zLogAppend("开启通道");
                endTime();
                break;

            case R.id.start:

                conn1PubKey = "";//i == 24
                conn2PubKey = "";//i == 25
                conn3PubKey = "";//i == 26
                conn4PubKey = "";//i == 27 len494
                conn4PubKey_1 = "";//i == 28 len22

                SM2_Cipher = "";
                RSA1024_PKCS1_PADDING_Cipher = "";
                RSA1024_NO_PADDING_Cipher = "";
                RSA2048_PKCS1_PADDING_Cipher = "";
                RSA2048_PKCS1_PADDING_Cipher_1 = "";
                RSA2048_PKCS1_PADDING_Cipher_2 = "";
                RSA2048_NO_PADDING_Cipher = "";
                RSA2048_NO_PADDING_Cipher_1 = "";
                RSA2048_NO_PADDING_Cipher_2 = "";

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        zLog("开始测试");
                        readTxtFile();
                    }
                }).start();

                break;
        }
    }

    private void readTxtFile() {

        String filePath =Environment.getExternalStorageDirectory() + "/apdu/apdu.txt";

        ArrayList<String> apduList = new ArrayList<>();
        List<DemoBean> demoBeanList = new ArrayList<>();
        boolean isSuccess = false;
        try {

            String encoding = "UTF-8";
            File file = new File(filePath);
            int count = 0;
            if (file.isFile() && file.exists()) { // 判断文件是否存在
                InputStreamReader read = new InputStreamReader(new FileInputStream(file), encoding);// 考虑到编码格式
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt = null;
                while ((lineTxt = bufferedReader.readLine()) != null) {//按行读取
                    if (!"".equals(lineTxt)) {
                        String reds = lineTxt;
                        apduList.add(reds);
                        count++;
                    }
                }
                read.close();//关闭InputStreamReader
                bufferedReader.close();//关闭BufferedReader
            } else {
                System.out.println("找不到指定的文件");
            }

        } catch (Exception e) {

        }

        for (int i = 0; i < apduList.size(); i++) {
            String[] split = apduList.get(i).split("：");
            Log.d(TAG, split[0]);
            Log.d(TAG, split[1]);

            String string1 = "";

            String apdu = "";

            if(i == 29){
                apdu = "180A010180" + conn1PubKey.toUpperCase();
            } else if(i == 30){
                apdu = "180A020240" + conn2PubKey.toUpperCase();
            } else if(i == 31){
                apdu = "180A030180" + conn3PubKey.toUpperCase();
            } else if(i == 32){
                apdu = "180A040080" + conn4PubKey.substring(0, conn4PubKey.length() / 2).toUpperCase();
            } else if(i == 33){
                apdu = "180A048080" + conn4PubKey.substring(conn4PubKey.length() / 2, conn4PubKey.length()).toUpperCase();
            } else if(i == 47){
                //SM2解密
                apdu = "180C022066" + SM2_Cipher.toUpperCase();
            } else if(i == 48){
                //RSA1024_PKCS1_PADDING解密
                apdu = "180C031280" + RSA1024_PKCS1_PADDING_Cipher.toUpperCase();
            } else if(i == 49){
                //RSA1024_NO_PADDING解密
                apdu = "180C031080" + RSA1024_NO_PADDING_Cipher.toUpperCase();
            } else if(i == 50){
                //RSA2048_PKCS1_PADDING解密 1包
                apdu = "180C048280" + RSA2048_PKCS1_PADDING_Cipher.substring(0, RSA2048_PKCS1_PADDING_Cipher.length() / 2).toUpperCase();
            } else if(i == 51){
                //RSA2048_PKCS1_PADDING解密 2包
                apdu = "180C040280" + RSA2048_PKCS1_PADDING_Cipher.substring(RSA2048_PKCS1_PADDING_Cipher.length() / 2, RSA2048_PKCS1_PADDING_Cipher.length()).toUpperCase();
            } else if(i == 52){
                //RSA2048_NO_PADDING解密 1包
                apdu = "180C048080" + RSA2048_PKCS1_PADDING_Cipher.substring(0, RSA2048_PKCS1_PADDING_Cipher.length() / 2).toUpperCase();
            } else if(i == 53){
                //RSA2048_NO_PADDING解密 2包
                apdu = "180C040080" + RSA2048_PKCS1_PADDING_Cipher.substring(RSA2048_PKCS1_PADDING_Cipher.length() / 2, RSA2048_PKCS1_PADDING_Cipher.length()).toUpperCase();
            } else {
                apdu = split[1];
            }

            beginTime();

            string1 = mSafetyCardMT2.sendAPDU(apdu);

            if(string1.endsWith("9000")){
                isSuccess = true;
                zLogAppend(i + ":" + split[0] + ":" + "成功" + isSuccess);
            } else {
                isSuccess = false;
                zLogAppend(i + ":" + split[0] + ":" + "失败" + isSuccess);
            }
            endTime();

            if(i == 24){
                conn1PubKey = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "conn1PubKey====" + conn1PubKey);
            } else if(i == 25){
                conn2PubKey = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "conn2PubKey====" + conn2PubKey);
            } else if(i == 26){
                conn3PubKey = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "conn3PubKey====" + conn3PubKey);
            } else if(i == 27){
                conn4PubKey = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "conn4PubKey====" + conn4PubKey);
            } else if(i == 28){
                conn4PubKey_1 = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "conn4PubKey_1====" + conn4PubKey_1);
                conn4PubKey = conn4PubKey + conn4PubKey_1;
                Log.d(TAG, "conn4PubKey ALL====" + conn4PubKey);
            } else if(i == 39){
                SM2_Cipher = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "SM2_Cipher====" + SM2_Cipher);
            } else if(i == 40){
                RSA1024_PKCS1_PADDING_Cipher = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "RSA1024_PKCS1_PADDING_Cipher====" + RSA1024_PKCS1_PADDING_Cipher);
            } else if(i == 41){
                RSA1024_NO_PADDING_Cipher = string1.substring(4, string1.length() - 4);
                Log.d(TAG, "RSA1024_NO_PADDING_Cipher====" + RSA1024_NO_PADDING_Cipher);
            } else if(i == 42){
                RSA2048_PKCS1_PADDING_Cipher_1 = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "RSA2048_PKCS1_PADDING_Cipher_1====" + RSA2048_PKCS1_PADDING_Cipher_1);
            } else if(i == 43){
                RSA2048_PKCS1_PADDING_Cipher_2 = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "RSA2048_PKCS1_PADDING_Cipher_2====" + RSA2048_PKCS1_PADDING_Cipher_2);
                RSA2048_PKCS1_PADDING_Cipher = RSA2048_PKCS1_PADDING_Cipher_1 + RSA2048_PKCS1_PADDING_Cipher_2;
                Log.d(TAG, "RSA2048_PKCS1_PADDING_Cipher====" + RSA2048_PKCS1_PADDING_Cipher);
            } else if(i == 45){
                RSA2048_NO_PADDING_Cipher_1 = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "RSA2048_NO_PADDING_Cipher_1====" + RSA2048_NO_PADDING_Cipher_1);
            } else if(i == 46){
                RSA2048_NO_PADDING_Cipher_2 = string1.substring(4, string1.length() - 8);
                Log.d(TAG, "RSA2048_NO_PADDING_Cipher_2====" + RSA2048_NO_PADDING_Cipher_2);
                RSA2048_NO_PADDING_Cipher = RSA2048_NO_PADDING_Cipher_1 + RSA2048_NO_PADDING_Cipher_2;
                Log.d(TAG, "RSA2048_NO_PADDING_Cipher====" + RSA2048_NO_PADDING_Cipher);
            }

            DemoBean demoBean = new DemoBean(i + ":" + split[0], (mEndTime - mBeginTime), isSuccess);
            demoBeanList.add(demoBean);

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }

        exportExcel(this,demoBeanList);
    }

    private void exportExcel(Context context, List<DemoBean> demoBeanList) {

        String filePath = Environment.getExternalStorageDirectory() + "/apdu/AutoTest7816.xls";

        String[] title = {"指令名称", "耗时 ms", "是否执行成功"};

        String sheetName = "AutoTest";

        ExcelUtil.initExcel(filePath, sheetName, title);


        ExcelUtil.writeObjListToExcel(demoBeanList, filePath, context);

    }

    private void openChannel() {
        try {
            mSafetyCardMT2.openChannel(new SafetyCardMT2.SupportCallBack() {
                @Override
                public void isSupport(boolean b) {
                    if (b) {
                        zLog("发现卡片");
                        zLogAppend("通道：" + mSafetyCardMT2.getChannelType());
                    } else {
                        zLog("未发现卡片");
                    }
                }
            });
        } catch (Exception e) {
            zLog("未发现卡片");
        }
    }


    private long mBeginTime;
    private long mEndTime;

    public void beginTime() {
        mBeginTime = System.currentTimeMillis();
    }

    public void endTime() {
        mEndTime = System.currentTimeMillis();
        zLogAppend("用时：" + (mEndTime - mBeginTime) + "ms");
        zLogAppend("");
    }

    private void zLog(final String str) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                mRet.setText(str + "\n");
                Log.d(TAG, str);
            }
        });
    }

    private void zLogAppend(final String str) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                mRet.append(str + "\n");
                Log.d(TAG, str);
            }
        });
    }

}
