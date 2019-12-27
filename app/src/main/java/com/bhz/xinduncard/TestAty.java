package com.bhz.xinduncard;

import android.Manifest;
import android.annotation.TargetApi;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import com.csizg.securitymt2.SafetyCardMT2;
import java.util.ArrayList;
import java.util.List;

public class TestAty extends AppCompatActivity {
    @BindView(R.id.btn_create_mf) Button btnCreateMf;
    @BindView(R.id.btn_delete_mf) Button btnDeleteMf;
    @BindView(R.id.btn_create_key) Button btnCreateKey;
    @BindView(R.id.btn_write_key) Button btnWriteKey;
    private SafetyCardMT2 mSafetyCardMT2;
    private String TAG = "TestAty";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_aty);
        ButterKnife.bind(this);
        // 申请通用权限
        if (Build.VERSION.SDK_INT >= 23) {
            String[] permissions = requestPermissions();
            if (permissions != null) {
                requestPermissions(permissions, 1003);
                return;
            }
        }
        mSafetyCardMT2 = new SafetyCardMT2(this);
        openChannel();
    }
    @OnClick({ R.id.btn_create_mf, R.id.btn_delete_mf, R.id.btn_create_key, R.id.btn_write_key })
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_create_mf:
                createMF();
                break;
            case R.id.btn_delete_mf:
                deleteMF();
                break;
            case R.id.btn_create_key:
                break;
            case R.id.btn_write_key:
                break;
        }
    }
    //创建MF
    private void createMF(){
        String[] mf = mSafetyCardMT2.createMF();
        if(SafetyCardMT2.RES_OK.equals(mf[0])){
            Log.d(TAG,"创建MF"+mf[1]);
        }else {
            Log.d(TAG,"创建MF"+mf[0]);
        }
    }
    //删除MF
    private void deleteMF(){
        String[] delMF = mSafetyCardMT2.delMF();
        if(SafetyCardMT2.RES_OK.equals(delMF[0])){
            Log.d(TAG,"删除MF"+delMF[1]);
        }else {
            Log.d(TAG,"删除MF"+delMF[0]);
        }
    }
    //创建key文件
    private void createKey(){
        String[] key = mSafetyCardMT2.createKey();
        if(SafetyCardMT2.RES_OK.equals(key[0])){
            Log.d(TAG,"创建Key"+key[1]);
        }else {
            Log.d(TAG,"创建Key"+key[0]);
        }
    }

    /**
     * 装载或者更新key值
     * @param keyType 00：MK_MF    主控秘钥->控制MF下文件的建立和秘钥的写入,作为默认的外部认证秘钥
     *                00: MK_DF01  主控秘钥->控制DF下文件的建立和秘钥的写入,作为默认的外部认证秘钥
     *                01: DAMK_MF  系统维护秘钥->发卡方用于产生更新二进制文件或记录命令的MAC
     *                01：DAMK_DF01 应用维护秘钥->应用提供方用于产生更新二进制文件或记录命令的MAC
     *                02：ETK_DF01  外部认证秘钥->用于载体鉴别终端身份，鉴别通过后改变应用安全状态
     *                03：ITK_DF01  内部认证秘钥->用于终端鉴别载体身份
     *                0A: PIN_DF01  鉴别密码PIN->用于载体鉴别用户身份
     *                07：PUK_DF01  PIN解锁秘钥->用于解锁PIN
     *                08：RPK_DF01  重装秘钥->用于重装PIN
     *
     * @param keyId  01：SM4   02:3DES
     * @param data
     * @param isPlain true:明文装载  false：秘文装载
     */
    private void writeKey(String keyType,String keyId,String data,boolean isPlain){
        mSafetyCardMT2.writeKey(keyType,keyId,data,isPlain);
    }














































    //开启通道
    private void openChannel() {
        try {
            mSafetyCardMT2.openChannel(new SafetyCardMT2.SupportCallBack() {
                @Override
                public void isSupport(boolean b) {
                    if (b) {
                        Log.d(TAG, "通道" + mSafetyCardMT2.getChannelType());
                    } else {
                        Log.d(TAG, "未发现卡片");
                    }
                }
            });
        } catch (Exception e) {
            Log.d(TAG, "未未发现卡片");
        }
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
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
            @NonNull int[] grantResults) {
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
            //            mSafetyCardMT2.setFlag(cb1Flag, cb2Flag, cb3Flag, cb4Flag, cb5Flag, cb6Flag);
            //            mSafetyCard.setPrintLog(true);
            //            mUCard=new UCard(this,cb1Flag,cb2Flag,cb3Flag,cb4Flag);
            //            mUcardAPI=new UcardAPI(this);
        }
    }


}
