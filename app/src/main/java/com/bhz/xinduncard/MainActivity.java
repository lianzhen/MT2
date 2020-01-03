package com.bhz.xinduncard;

import android.Manifest;
import android.annotation.TargetApi;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.csizg.securitymt2.SafetyCardMT2;
import com.bhz.xinduncard.FileManager;
import com.bhz.xinduncard.SM4;
import com.bhz.xinduncard.SM4_Context;
import com.bhz.xinduncard.SM3Digest;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.encoders.HexEncoder;

import static jxl.biff.StringHelper.getBytes;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    protected static final String TAG = "MainActivity";
    private TextView mRet;
    private EditText mSenddata;
    private String capdu;
    private CheckBox cb1, cb2, cb3, cb4, cb5, cb6;
    private static SafetyCardMT2 mSafetyCardMT2;
    private boolean cb1Flag = false, cb2Flag = true, cb3Flag = true, cb4Flag = true, cb5Flag = true,
            cb6Flag = true;
    private Handler handler = new Handler();

    private String mPubKey1 = "";
    private String mPubKey2 = "";
    private String mPubKey3 = "";
    private String mPubKey4 = "";
    private String mSN = "";
    private String mPUK = "";

    private String mSM3Digest = "";
    private String mSHA1Digest = "";
    private String mSHA256Digest = "";

    private String signSM2Digest = "";
    private String signRSADigest = "";
    private String signRSA2048Digest = "";

    private String mPlain = "112233445566";
    //    private String mPlain96 = "0102030405060708010203040506070801020304050607080102030405060708112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233445566889900AABBCCDDEEFF112233";
    private String mPlain96 =
            "01020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708";
    //    private String mPlain1024 = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344";
    private String mPlain1024 =
            "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF";

    private String mPlainData = "";

    private String mCipherSM2 = "";
    private String mCipherRSA1024p = "";
    private String mCipherRSA1024no = "";
    private String mCipherRSA2048p = "";
    private String mCipherRSA2048no = "";

    private Button sM2Test;
    private String tarPublicKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.open).setOnClickListener(this);
        findViewById(R.id.sendapdu).setOnClickListener(this);
        findViewById(R.id.get_info).setOnClickListener(this);
        findViewById(R.id.get_info_jar).setOnClickListener(this);
        findViewById(R.id.test).setOnClickListener(this);
        findViewById(R.id.get_random).setOnClickListener(this);
        findViewById(R.id.login).setOnClickListener(this);
        findViewById(R.id.logout).setOnClickListener(this);
        findViewById(R.id.change_pin).setOnClickListener(this);
        findViewById(R.id.reset_pin).setOnClickListener(this);
        findViewById(R.id.create_container_01).setOnClickListener(this);
        findViewById(R.id.del_container_01).setOnClickListener(this);
        findViewById(R.id.get_container_info).setOnClickListener(this);
        findViewById(R.id.change_container).setOnClickListener(this);
        findViewById(R.id.create_keyPair).setOnClickListener(this);
        findViewById(R.id.get_pub_key).setOnClickListener(this);
        findViewById(R.id.imp_pub_key).setOnClickListener(this);
        findViewById(R.id.get_pub_key_ex).setOnClickListener(this);
        findViewById(R.id.enc_SM2_RSA).setOnClickListener(this);
        findViewById(R.id.dec_SM2_RSA).setOnClickListener(this);
        findViewById(R.id.create_symmetric_key).setOnClickListener(this);
        findViewById(R.id.enu_symmetric_key).setOnClickListener(this);
        findViewById(R.id.del_symmetric_key).setOnClickListener(this);
        findViewById(R.id.exp_symmetric_key).setOnClickListener(this);
        findViewById(R.id.imp_symmetric_key).setOnClickListener(this);
        findViewById(R.id.calc_symmetric_key).setOnClickListener(this);
        findViewById(R.id.calc_digest).setOnClickListener(this);
        findViewById(R.id.sign_sm2_rsa).setOnClickListener(this);
        findViewById(R.id.verify_sm2_rsa).setOnClickListener(this);
        findViewById(R.id.write_file).setOnClickListener(this);
        findViewById(R.id.read_file).setOnClickListener(this);
        findViewById(R.id.sign_sm2).setOnClickListener(this);
        findViewById(R.id.sign_rsa).setOnClickListener(this);
        findViewById(R.id.verify_sm2).setOnClickListener(this);
        findViewById(R.id.verify_rsa).setOnClickListener(this);
        findViewById(R.id.sm2_calc).setOnClickListener(this);
        findViewById(R.id.sm2_sing_verify).setOnClickListener(this);
        findViewById(R.id.sm3_calc).setOnClickListener(this);
        findViewById(R.id.sm4_calc).setOnClickListener(this);

        findViewById(R.id.del_mf).setOnClickListener(this);
        findViewById(R.id.create_mf).setOnClickListener(this);
        findViewById(R.id.create_key).setOnClickListener(this);
        findViewById(R.id.read_binary).setOnClickListener(this);
        findViewById(R.id.select_file).setOnClickListener(this);
        findViewById(R.id.get_challenge).setOnClickListener(this);
        findViewById(R.id.user_login).setOnClickListener(this);
        findViewById(R.id.session_key).setOnClickListener(this);
        findViewById(R.id.digestCal).setOnClickListener(this);
        findViewById(R.id.sm2).setOnClickListener(this);
        findViewById(R.id.SymmKey).setOnClickListener(this);
        findViewById(R.id.rsa).setOnClickListener(this);
        findViewById(R.id.file_test).setOnClickListener(this);
        findViewById(R.id.file_test1).setOnClickListener(this);
        findViewById(R.id.safety_house).setOnClickListener(this);
        findViewById(R.id.safety_house1).setOnClickListener(this);
        findViewById(R.id.sm4_speed_test).setOnClickListener(this);
        findViewById(R.id.sm2_speed_test).setOnClickListener(this);
        findViewById(R.id.get_1121).setOnClickListener(this);
        findViewById(R.id.sm2Test).setOnClickListener(this);
        findViewById(R.id.sha1_digest).setOnClickListener(this);
        findViewById(R.id.sha256_digest).setOnClickListener(this);
        findViewById(R.id.sm3_digest).setOnClickListener(this);
        findViewById(R.id.import_publicKey_Empty).setOnClickListener(this);
        findViewById(R.id.import_publicKey_NoEmpty).setOnClickListener(this);
        findViewById(R.id.create_file).setOnClickListener(this);
        findViewById(R.id.sign_btn).setOnClickListener(this);

        mRet = (TextView) findViewById(R.id.result);
        mSenddata = (EditText) findViewById(R.id.senddata);

        cb1 = (CheckBox) findViewById(R.id.cb1);
        cb2 = (CheckBox) findViewById(R.id.cb2);
        cb3 = (CheckBox) findViewById(R.id.cb3);
        cb4 = (CheckBox) findViewById(R.id.cb4);
        cb5 = (CheckBox) findViewById(R.id.cb5);
        cb6 = (CheckBox) findViewById(R.id.cb6);

        initCheckBox();
        // 申请通用权限
        if (Build.VERSION.SDK_INT >= 23) {
            String[] permissions = requestPermissions();
            if (permissions != null) {
                requestPermissions(permissions, 1003);
                return;
            }
        }
        mSafetyCardMT2 = new SafetyCardMT2(this);
        mSafetyCardMT2.setPrintLog(true);
        //        mSafetyCardMT2.setFlag(cb1Flag, cb2Flag, cb3Flag, cb4Flag, cb5Flag, cb6Flag);
    }

    @Override
    public void onClick(View view) {
        //        mSafetyCardMT2.setFlag(cb1Flag, cb2Flag, cb3Flag, cb4Flag, cb5Flag, cb6Flag);
        switch (view.getId()) {
            case R.id.open:
                beginTime();
                openChannel();
                endTime();
                break;
            case R.id.sendapdu:
                capdu = mSenddata.getText().toString();
                sendAPDU(capdu);
                break;

            case R.id.del_mf:
                beginTime();
                del_mf();
                endTime();
                break;

            case R.id.create_mf:
                beginTime();
                create_mf();
                endTime();
                break;

            case R.id.create_key:
                beginTime();
                create_key();
                endTime();
                break;

            case R.id.read_binary:
                //                beginTime();
                read_binary();
                //                read_binary_skf();
                //                endTime();
                break;

            case R.id.select_file:
                //                beginTime();
                select_file();
                //                endTime();
                break;
            case R.id.get_challenge:
                beginTime();
                get_challenge();
                endTime();
                break;
            case R.id.user_login:
                beginTime();
                user_login();
                endTime();
                break;
            case R.id.session_key:
                //                beginTime();
                session_key();
                //                endTime();
                break;
            case R.id.digestCal:
                //                beginTime();
                digestCal();
                //                endTime();
                break;
            case R.id.sm2:
                //                beginTime();
                new Thread() {
                    public void run() {
                        sm2();
                    }

                    ;
                }.start();

                //                endTime();
                break;
            case R.id.SymmKey:
                //                beginTime();
                new Thread() {
                    public void run() {
                        SymmKey();
                    }

                    ;
                }.start();

                //                endTime();
                break;
            case R.id.rsa:
                //                beginTime();
                new Thread() {
                    public void run() {
                        rsa();
                    }

                    ;
                }.start();

                //                endTime();
                break;
            case R.id.safety_house:
                new Thread() {
                    public void run() {
                        beginTime();
                        safety_house();
                        endTime();
                    }

                    ;
                }.start();

                break;
            case R.id.safety_house1:
                //                new Thread() {
                //                    public void run() {
                //                        beginTime();
                //
                //                        endTime();
                //                    };
                //                }.start();
                safety_house1();
                break;

            case R.id.sm4_calc:
                new Thread() {
                    public void run() {
                        sm4_calc();
                    }

                    ;
                }.start();

                break;
            case R.id.sm4_speed_test:
                new Thread() {
                    public void run() {
                        sm4_speed_test();
                    }

                    ;
                }.start();

                break;
            case R.id.sm2_speed_test:
                new Thread() {
                    public void run() {
                        sm2_speed_test();
                    }

                    ;
                }.start();

                break;
            case R.id.get_1121:
                new Thread() {
                    public void run() {
                        test_1121();
                    }
                }.start();

                break;

            case R.id.sm2Test:

                new Thread() {
                    public void run() {
                        testSM2();
                    }
                }.start();
                break;
            case R.id.sha1_digest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        test_sha1_digest();
                    }
                }).start();

                break;
            case R.id.sha256_digest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        test_sha256_digest();
                    }
                }).start();

                break;
            case R.id.sm3_digest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        test_sm3_digest();
                    }
                }).start();
                break;
            case R.id.create_file:
                createPubAndPriFile();
                break;
            case R.id.import_publicKey_Empty:
                //空文件下导入公钥--并导出公钥
                importPublicKey(true);
                break;
            case R.id.import_publicKey_NoEmpty:
                //文件下已经存在公钥的情况下导入公钥--并导出公钥
                importPublicKey(false);
                break;
            case R.id.sign_btn:
                testPriKeySign();
                break;
        }
    }

    private void testSM2() {
        //关联创建的公私秘钥 公钥的文件标识符 私钥的文件标识符 01：导出公钥  00：不导出公钥
        String[] result5 = mSafetyCardMT2.generateSM2Key("0201", "0202", "01");
        if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
            zLogAppend("产生SM2密钥对，并同时导出公钥:" + result5[1]);
            //导出利用API公钥
            ;
            zLogAppend("直接导出公钥:" + mSafetyCardMT2.exportSM2PublicKey("0201")[1]);
        } else {
            zLogAppend("产生SM2密钥对，并同时导出公钥" + result5[0]);
        }
        //加密操作
        //String str="0011223344556677889988AABBCCDDEE";
        String str = "今天吃饭了吗";
        str = Util.getHexString(str.getBytes());
        String miwen;
        String[] result6 = mSafetyCardMT2.SM2PublicKeyEnc("0201", str);
        if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
            zLogAppend("SM2 加密:" + result6[1]);
            miwen = result6[1];
        } else {
            zLogAppend("SM2 加密" + result6[0]);
            miwen = result6[0];
        }
        //解密操作
        String[] result7 = mSafetyCardMT2.SM2PrivateKeyDec("0202", miwen);
        if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
            byte[] b = Util.hexStringToBytes(result7[1]);
            String res = null;
            try {
                res = new String(b, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            zLogAppend("SM2 解密成功:" + res);
        } else {
            zLogAppend("SM2 解密" + result7[0]);
        }
    }

    private void test_sha1_digest() {
        try {

            //            String data = "3031300d0609608648016503040206053031300d0609608648016503040206053031300d060960864801650304020605";
            String data = "646541321676431678";
            beginTime();
            String[] result1 = mSafetyCardMT2.digestCal("01", "01", data);
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLog("SHA-1 摘要:" + result1[1]);
            } else {
                zLog("SHA-1 摘要 error" + result1[0]);
            }
            zLogAppend("SHA-1 摘要 " + endTimeA());
            zLogAppend("");
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void test_sha256_digest() {
        try {

            //            String data = "3031300d0609608648016503040206053031300d0609608648016503040206053031300d060960864801650304020605";
            String data = "646541321676431678";

            beginTime();
            String[] result2 = mSafetyCardMT2.digestCal("01", "02", data);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("SHA-256 摘要:" + result2[1]);
            } else {
                zLogAppend("SHA-256 摘要 error" + result2[0]);
            }
            zLogAppend("SHA-256 摘要 " + endTimeA());
            zLogAppend("");
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void test_sm3_digest() {
        try {

            //            String data = "3031300d0609608648016503040206053031300d0609608648016503040206053031300d060960864801650304020605";
            String data = "646541321676431678";

            beginTime();
            String[] result3 = mSafetyCardMT2.digestCal("01", "03", data);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("SM3 摘要:" + result3[1]);
            } else {
                zLogAppend("SM3 摘要 error" + result3[0]);
            }
            zLogAppend("SM3 摘要 " + endTimeA());
            zLogAppend("");
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void createPubAndPriFile() {
        //创建公钥文件
        mSafetyCardMT2.createSM2PubkeyFile("0270");
        mSafetyCardMT2.createSM2PubkeyFile("0272");
        mSafetyCardMT2.createSM2PubkeyFile("0274");
        mSafetyCardMT2.createSM2PrikeyFile("0271");
        mSafetyCardMT2.createSM2PrikeyFile("0273");
        mSafetyCardMT2.createSM2PubkeyFile("0275");

        //关联文件并创建公私密钥对
        String a[] = mSafetyCardMT2.generateSM2Key("0270", "0271", "01");
        tarPublicKey = a[1];
        zLogAppend("导出创建的公钥0270" + a[1]);
    }

    private void importPublicKey(boolean isEmpty) {
        if (!isEmpty) {
            //关联文件并创建公私密钥对
            String b[] = mSafetyCardMT2.generateSM2Key("0272", "0273", "01");
            zLogAppend("导出创建的公钥0272" + b[1]);
            //导入公钥
            mSafetyCardMT2.importSM2PubKey("0272", tarPublicKey);
            //导出公钥
            String c[] = mSafetyCardMT2.exportSM2PublicKey("0272");
            zLogAppend("导出创建的公钥0272" + c[1]);
        } else {
            //导入公钥
            mSafetyCardMT2.importSM2PubKey("0274", tarPublicKey);
            //导出公钥
            String d[] = mSafetyCardMT2.exportSM2PublicKey("0274");
            zLogAppend("导出创建的公钥0274" + d[1]);
        }
    }

    private void testPriKeySign() {
        String hashData = "";
        String signData = "";
        String[] result8 = mSafetyCardMT2.digestCal("01", "03", "12345678");
        if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
            hashData = result8[1];
        }
        //对摘要用私钥加签
        String[] result9 = mSafetyCardMT2.SM2PrivateKeySign("0202", hashData);
        if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
            signData = result9[1];
        }
        //公钥进行验签
        String result10[] = mSafetyCardMT2.SM2PublicKeyVerify("0201", hashData, signData);
        if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
            zLogAppend("验签结果：" + "成功");
        }
    }

    private void test_1121() {
        try {

            beginTime();
            String[] result1 = mSafetyCardMT2.selectFile("00", "1121");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                endTime2();
                zLog("选择 1121目录成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLog("选择 1121目录失败！" + "用时：" + mUseTime + "ms");
            }

            beginTime();
            String[] result2 = mSafetyCardMT2.verifyPIN("313233343536");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                endTime2();
                zLogAppend("验证PIN成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("验证PIN error！" + "用时：" + mUseTime + "ms");
            }

            zLogAppend("********** Update ID_Key 开始！**********");

            String New_IDKey = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF";
            String KKeyAB = "00AABBCCDDEEFF11223344556677889900AABBCCDDEEFF112233445566778899";

            byte bData[] = new byte[32];
            SM4 sm4 = new SM4();
            SM4_Context context = new SM4_Context();
            context.isPadding = false;
            try {
                sm4.sm4_setkey_enc(context,
                        FileManager.hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
                bData = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(New_IDKey));
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte bData1[] = new byte[32];
            String[] res = mSafetyCardMT2.getChallengeA("10");
            String challenge = res[1] + "80000000000000000000000000000000";
            try {
                sm4.sm4_setkey_enc(context,
                        FileManager.hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
                bData1 = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(challenge));
            } catch (Exception e) {
                e.printStackTrace();
            }

            String data = FileManager.bytesToHex(bData) + FileManager.bytesToHex(bData1);
            Log.d(TAG, "data == " + data);

            beginTime();
            String[] result3 = mSafetyCardMT2.updateIDKey(data);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                endTime2();
                zLogAppend("Update ID_Key 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("Update ID_Key error！" + "用时：" + mUseTime + "ms");
            }
            zLogAppend("********** Update ID_Key 结束！**********");
            zLogAppend("");
            zLogAppend("********** Register 第一步 开始！**********");

            byte bData2[] = new byte[32];
            String[] res2 = mSafetyCardMT2.getChallenge("20");
            String challenge2 = res2[1];
            try {
                sm4.sm4_setkey_enc(context,
                        FileManager.hexToBytes("11223344556677889900AABBCCDDEEFF"));
                bData2 = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(challenge2));
            } catch (Exception e) {
                e.printStackTrace();
            }

            String data2 = FileManager.bytesToHex(bData2);

            String register01 = "";
            beginTime();
            String[] result4 = mSafetyCardMT2.register("01", data2);
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                endTime2();
                register01 = result4[1];
                zLogAppend("register 01 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("register 01 error！" + "用时：" + mUseTime + "ms");
            }
            zLogAppend("********** Register 第一步 结束！**********");
            zLogAppend("");
            zLogAppend("********** Register 第二步 开始！**********");
            beginTime();
            String[] result5 = mSafetyCardMT2.register("02", register01.substring(64));
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                endTime2();
                zLogAppend("register 02 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("register 02 error！" + "用时：" + mUseTime + "ms");
            }
            zLogAppend("********** Register 第二步 结束！**********");
            zLogAppend("");
            zLogAppend("********** importProtectionKey 开始！**********");

            byte BData1[] = new byte[32];
            byte BData2[] = new byte[32];
            try {
                sm4.sm4_setkey_dec(context,
                        FileManager.hexToBytes("11223344556677889900AABBCCDDEEFF"));
                BData1 = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(register01.substring(0, 64)));
                BData2 = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(register01.substring(64)));
                Log.d(TAG, "BData1:" + FileManager.bytesToHex(BData1));
                Log.d(TAG, "BData2:" + FileManager.bytesToHex(BData2));
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] result = new byte[32];
            byte[] resultT = new byte[32];
            for (int i = 0; i < 32; i++) {
                resultT[i] = (byte) (BData1[i] ^ 0xFF);
                result[i] = (byte) (resultT[i] ^ BData2[i]);
            }

            Log.d(TAG, "密钥加密密钥（密钥3）:" + FileManager.bytesToHex(result));
            try {
                sm4.sm4_setkey_enc(context,
                        FileManager.hexToBytes(FileManager.bytesToHex(result).substring(0, 32)));
                bData2 = sm4.sm4_crypt_cbc(context,
                        FileManager.hexToBytes("00000000000000000000000000000000"),
                        FileManager.hexToBytes(KKeyAB));
            } catch (Exception e) {
                e.printStackTrace();
            }

            beginTime();
            String[] result6 =
                    mSafetyCardMT2.importProtectionKey("0002", FileManager.bytesToHex(bData2));
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                endTime2();
                zLogAppend("importProtectionKey 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("importProtectionKey error！" + "用时：" + mUseTime + "ms");
            }
            zLogAppend("********** importProtectionKey 结束！**********");
            zLogAppend("");
            zLogAppend("********** sessionKey Crypt 开始！**********");

            String[] res3 = mSafetyCardMT2.getChallenge("40");
            String challenge3 = res3[1];
            Log.d(TAG, "sessionKeyEncrypt challenge3:" + challenge3);

            SM3Digest sm3Digest = new SM3Digest();
            byte[] src = FileManager.hexToBytes(challenge3);
            sm3Digest.update(src, 0, src.length);
            byte[] md = new byte[sm3Digest.getDigestSize()];
            sm3Digest.doFinal(md, 0);
            String hash = FileManager.bytesToHex(md);
            Log.d(TAG, "sessionKeyEncrypt hash:" + hash);

            beginTime();
            String[] result7 = mSafetyCardMT2.sessionKeyEncrypt("0002", "00", challenge3, hash);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                endTime2();
                Log.d(TAG, "sessionKeyEncrypt cipher:" + result7[1]);
                zLogAppend("sessionKeyEncrypt 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("sessionKeyEncrypt error！" + "用时：" + mUseTime + "ms");
            }

            String[] res4 = mSafetyCardMT2.getChallenge("20");
            String challenge4 = res4[1];

            sm4.sm4_setkey_enc(context, FileManager.hexToBytes("00AABBCCDDEEFF112233445566778899"));
            byte[] bData11 = sm4.sm4_crypt_cbc(context,
                    FileManager.hexToBytes("00000000000000000000000000000000"),
                    FileManager.hexToBytes(challenge4));

            String[] res5 = mSafetyCardMT2.getChallenge("60");
            String challenge5 = res5[1];

            SM3Digest sm3Digest1 = new SM3Digest();
            byte[] src1 = FileManager.hexToBytes(challenge5);
            sm3Digest1.update(src1, 0, src1.length);
            byte[] md1 = new byte[sm3Digest1.getDigestSize()];
            sm3Digest1.doFinal(md1, 0);
            String hash1 = FileManager.bytesToHex(md1);

            String data22 = challenge5 + hash1;

            sm4.sm4_setkey_enc(context, FileManager.hexToBytes(challenge4.substring(0, 32)));
            byte[] bData33 = sm4.sm4_crypt_cbc(context,
                    FileManager.hexToBytes("00000000000000000000000000000000"),
                    FileManager.hexToBytes(data22));

            beginTime();
            String[] result8 =
                    mSafetyCardMT2.sessionKeyDecrypt("0002", "00", FileManager.bytesToHex(bData11),
                            FileManager.bytesToHex(bData33));
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                endTime2();
                Log.d(TAG, "sessionKeyDecrypt plain:" + result8[1]);
                zLogAppend("sessionKeyDecrypt 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("sessionKeyDecrypt error！" + "用时：" + mUseTime + "ms");
            }
            zLogAppend("********** sessionKey Crypt 结束！**********");
            zLogAppend("");

            beginTime();
            String[] result9 = mSafetyCardMT2.exportSeedKey("0002");
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                endTime2();
                Log.d(TAG, "exportSeedKey SeedKey:" + result9[1]);
                zLogAppend("exportSeedKey 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("exportSeedKey error！" + "用时：" + mUseTime + "ms");
            }

            String[] res6 = mSafetyCardMT2.getChallenge("80");
            String challenge6 = res6[1];

            beginTime();
            String[] result10 = mSafetyCardMT2.conversationDataEncrypt("00000001", challenge6);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                endTime2();
                Log.d(TAG, "conversationDataEncrypt SeedKey1:" + result10[1]);
                zLogAppend("conversationDataEncrypt 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("conversationDataEncrypt error！" + "用时：" + mUseTime + "ms");
            }

            String[] res7 = mSafetyCardMT2.getChallenge("20");
            String challenge7 = res7[1];

            sm4.sm4_setkey_enc(context, FileManager.hexToBytes("00AABBCCDDEEFF112233445566778899"));
            bData11 = sm4.sm4_crypt_cbc(context,
                    FileManager.hexToBytes("00000000000000000000000000000000"),
                    FileManager.hexToBytes(challenge7));

            beginTime();
            String[] result11 =
                    mSafetyCardMT2.importSeedKey("0002", FileManager.bytesToHex(bData11));
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                endTime2();
                zLogAppend("importSeedKey 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("importSeedKey error！" + "用时：" + mUseTime + "ms");
            }

            String packge = "00000001";
            String[] res8 = mSafetyCardMT2.getChallenge("80");
            String challenge8 = res8[1];

            sm4.sm4_setkey_enc(context, FileManager.hexToBytes(challenge7.substring(0, 32)));
            bData = sm4.sm4_crypt_cbc(context,
                    FileManager.hexToBytes("00000000000000000000000000000000"),
                    FileManager.hexToBytes(challenge7));

            sm4.sm4_setkey_enc(context,
                    FileManager.hexToBytes(FileManager.bytesToHex(bData).substring(0, 32)));
            byte[] bData3 = sm4.sm4_crypt_cbc(context,
                    FileManager.hexToBytes("00000000000000000000000000000000"),
                    FileManager.hexToBytes(challenge8));

            beginTime();
            String[] result12 =
                    mSafetyCardMT2.conversationDataDecrypt(packge, FileManager.bytesToHex(bData3));
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                endTime2();
                zLogAppend("conversationDataDecrypt 成功！" + "用时：" + mUseTime + "ms");
            } else {
                endTime2();
                zLogAppend("conversationDataDecrypt error！" + "用时：" + mUseTime + "ms");
            }
        } catch (Exception e) {
        }
    }

    private void sm2_speed_test() {

        try {

            beginTime();
            mSafetyCardMT2.getCardInfo("01", "08");
            endTime2();
            zLog("\ngetCardNum," + "用时：" + mUseTime + "ms");

            beginTime();
            mSafetyCardMT2.getChallenge("10");
            endTime2();
            zLogAppend("\ngetRandom(10bytes)," + "用时：" + mUseTime + "ms");

            beginTime();
            mSafetyCardMT2.exportPublicKey("0201", "02", "00");
            endTime2();
            zLogAppend("\nsm2GetPubKey," + "用时：" + mUseTime + "ms");

            beginTime();
            String[] result =
                    mSafetyCardMT2.SM2PublicKeyEnc("0201", "0011223344556677889988AABBCCDDEE");
            endTime2();
            zLogAppend("\nsm2Encrypt(16bytes)," + "用时：" + mUseTime + "ms");

            beginTime();
            mSafetyCardMT2.SM2PrivateKeyDec("0202", result[1].toUpperCase());
            endTime2();
            zLogAppend("\nsm2Decrypt," + "用时：" + mUseTime + "ms");

            String hashData = "";
            String signData = "";
            String[] result8 = mSafetyCardMT2.digestCal("01", "03", "12345678");
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                hashData = result8[1];
            }

            beginTime();
            String[] result9 = mSafetyCardMT2.SM2PrivateKeySign("0202", hashData);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                signData = result9[1];
            }
            endTime2();
            zLogAppend("\nsm2Sign(32bytes)," + "用时：" + mUseTime + "ms");

            beginTime();
            mSafetyCardMT2.SM2PublicKeyVerify("0201", hashData, signData);
            endTime2();
            zLogAppend("\nsm2Verify(32bytes)," + "用时：" + mUseTime + "ms");

            String data =
                    "0102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708";

            beginTime();
            mSafetyCardMT2.digestCal("01", "03", data);
            mSafetyCardMT2.digestCal("01", "03", data);
            endTime2();
            zLogAppend("\nsm3Calc(256bytes)," + "用时：" + mUseTime + "ms");
        } catch (Exception e) {
        }
    }

    private void sm4_speed_test() {

        try {

            //            final String data = "0102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708";
            //            beginTime();
            //            mSafetyCardMT2.sessionKeyEncECB("01", "00000000", data);
            //            for (int i = 0; i < 6; i++) {
            //                mSafetyCardMT2.sessionKeyEncECB("02", "00000000", data);
            //            }
            //            String[] rec1 = mSafetyCardMT2.sessionKeyEncECB("03", "00000000", data);
            //            endTime2();
            //            zLog("\nsm4Encrypt(1024 bytes)," + "用时：" + mUseTime + "ms");
            //            double duration = mUseTime / 8.0000;
            //            double duration1 = 1024 * 8 * 1000.0000 / mUseTime / 1000.0000 * 1024 / 1000.0000;
            //            zLogAppend("平均单次" + "用时：" + duration + "ms" + "\n性能：" + duration1 + "Kbps");
            //
            //            beginTime();
            //            mSafetyCardMT2.sessionKeyDecECB("01", "00000000", rec1[1]);
            //            for (int i = 0; i < 6; i++) {
            //                mSafetyCardMT2.sessionKeyDecECB("02", "00000000", rec1[1]);
            //            }
            //            mSafetyCardMT2.sessionKeyDecECB("03", "00000000", rec1[1]);
            //            endTime2();
            //            zLogAppend("\nsm4Decrypt(1024 bytes)," + "用时：" + mUseTime + "ms");
            //            double duration2 = mUseTime / 8.0000;
            //            double duration3 = 1024 * 8 * 1000.0000 / mUseTime / 1000.0000 * 1024 / 1000.0000;
            //            zLogAppend("平均单次" + "用时：" + duration2 + "ms" + "\n性能：" + duration3 + "Kbps");

            String[] res2 = mSafetyCardMT2.TransmitSIMApdu("00A40804047F206F07");
            if (res2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res2[0])) {
                zLog("向SIM卡发指令:" + res2[1]);
            } else {
                zLog("向SIM卡发指令:" + res2[0]);
            }

            String[] res3 = mSafetyCardMT2.TransmitSIMApdu("00A40804067F105F3A4F5A");
            if (res3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res3[0])) {
                zLogAppend("向SIM卡发指令:" + res3[1]);
            } else {
                zLogAppend("向SIM卡发指令:" + res3[0]);
            }

            String[] res4 = mSafetyCardMT2.GetSIMIMSI();
            if (res4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res4[0])) {
                zLogAppend("获取SIM卡的IMSI:" + res4[1]);
            } else {
                zLogAppend("获取SIM卡的IMSI:" + res4[0]);
            }
        } catch (Exception e) {
        }
    }

    private void safety_house1() {

        String pubKey =
                "B9766242AF810574D9CF60B5D0A92B0D426E0E9B34F9A575ACAA64FD559330AA72D436A2C4BD2D71EF020520E650C721D63E6D1CB873FBD9C3E2712DC5E26E0B";
        String priKey = "8C96B7EB36950B97F3A77152030F2E216B87FC87E1971CB8AF7694858CA81E64";

        String DBAKEY1 = "1111111111111111111111111111111111111111111111111111111111111111";
        String DBAKEY2 = "2222222222222222222222222222222222222222222222222222222222222222";
        String DBAKEY3 = "3333333333333333333333333333333333333333333333333333333333333333";
        String DBAKEY4 = "4444444444444444444444444444444444444444444444444444444444444444";

        String SM2Cipher = "";
        String SM2Plain = "";

        String SM2PubKey = "";

        try {

            String[] res1 = mSafetyCardMT2.exportPublicKey("0201", "02", "00");
            if (res1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res1[0])) {
                zLog("SM2 导出公钥 0201:" + res1[1]);
                SM2PubKey = "0201" + res1[1].substring(4, 132);
            } else {
                zLog("SM2 导出公钥 0201" + res1[0]);
            }

            String[] res2 = mSafetyCardMT2.exportPublicKey("0203", "02", "00");
            if (res2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res2[0])) {
                zLog("SM2 导出公钥 0203:" + res2[1]);
                SM2PubKey = SM2PubKey + "0203" + res2[1].substring(4, 132);
            } else {
                zLog("SM2 导出公钥 0203" + res2[0]);
            }

            String[] res3 = mSafetyCardMT2.exportPublicKey("0205", "02", "00");
            if (res3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(res3[0])) {
                zLog("SM2 导出公钥 0205:" + res3[1]);
                SM2PubKey = "03" + SM2PubKey + "0205" + res3[1].substring(4, 132);
                zLog("SM2PubKey:" + SM2PubKey);
            } else {
                zLog("SM2 导出公钥 0205" + res3[0]);
            }

            String[] result = mSafetyCardMT2.exportSM2PubKeyByDBA("0001", "020102030205");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("指定DBA密钥加密导出SM2公钥 :" + result[1]);
                SM2Cipher = result[1].substring(2);
            } else {
                zLog("指定DBA密钥加密导出SM2公钥 error" + result[0]);
            }

            String[] result1 = mSafetyCardMT2.generateDBASessionKey(pubKey, "0201", "0001");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("公钥加密导出会话密钥 :" + result1[1]);
            } else {
                zLogAppend("公钥加密导出会话密钥 error" + result1[0]);
            }

            String SK = result1[1].substring(0, 256);
            String SK1 = result1[1].substring(256);

            Log.d(TAG, "SK =" + SK);
            Log.d(TAG, "SK1=" + SK1);
            String data = DBAKEY2;
            String cipher = "";

            String[] result4 = mSafetyCardMT2.encryptByDBASessionKey(data);
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("使用DBA会话密钥加密 :" + result4[1]);
                cipher = result4[1];
            } else {
                zLogAppend("使用DBA会话密钥加密 error" + result4[0]);
            }

            String[] result3 = mSafetyCardMT2.importDBASessionKey(SK, "0204", "0001");
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("导入使用DBAKey加密后的会话密钥 : 成功" + result3[1]);
            } else {
                zLogAppend("导入使用DBAKey加密后的会话密钥 error" + result3[0]);
            }

            String[] result5 = mSafetyCardMT2.decryptByDBASessionKey(cipher);
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("使用DBA会话密钥解密 :" + result5[1]);
            } else {
                zLogAppend("使用DBA会话密钥解密 error" + result5[0]);
            }

            String[] result6 = mSafetyCardMT2.importDBASessionKey(SK1, "0202", "0001");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("导入使用DBAKey加密后的会话密钥 : 成功" + result6[1]);
            } else {
                zLogAppend("导入使用DBAKey加密后的会话密钥 error" + result6[0]);
            }

            String[] result7 = mSafetyCardMT2.decryptByDBASessionKey(cipher);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("使用DBA会话密钥解密 :" + result7[1]);
            } else {
                zLogAppend("使用DBA会话密钥解密 error" + result7[0]);
            }

            String random = "";
            String signData = "";
            String hashData = "";
            String reHashData = "";
            String[] result8 = mSafetyCardMT2.getChallenge("70");
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                //                zLog("取随机数:" + result8[1]);
                random = result8[1];
            } else {
                zLogAppend("取随机数 error" + result8[0]);
            }

            String[] result9 = mSafetyCardMT2.digestCal("01", "03", random);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("SM3:" + result9[1]);
                hashData = result9[1];
            } else {
                zLogAppend("SM3 error" + result9[0]);
            }

            String[] result10 = mSafetyCardMT2.SM2PrivateKeySign("0204", hashData);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("SM2 sign:" + result10[1]);
                signData = result10[1];
            } else {
                zLogAppend("SM3 sign error" + result10[0]);
            }

            String[] result11 =
                    mSafetyCardMT2.SM2VerifyWithPubKey("00", pubKey, signData, hashData);
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("验签 ‘00’：数据不需卡内再次HASH: 成功" + result11[1]);
            } else {
                zLogAppend("验签 ‘00’：数据不需卡内再次HASH" + result11[0]);
            }

            String[] result12 = mSafetyCardMT2.getChallenge("70");
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                //                zLog("取随机数:" + result8[1]);
                random = result12[1];
            } else {
                zLogAppend("取随机数 error" + result12[0]);
            }

            String[] result13 = mSafetyCardMT2.digestCal("01", "03", random);
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("SM3:" + result13[1]);
                hashData = result13[1];
            } else {
                zLogAppend("SM3 error" + result13[0]);
            }

            String[] result14 = mSafetyCardMT2.digestCal("01", "03", hashData);
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("SM3:" + result14[1]);
                reHashData = result14[1];
            } else {
                zLogAppend("SM3 error" + result14[0]);
            }

            String[] result15 = mSafetyCardMT2.SM2PrivateKeySign("0204", reHashData);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("SM2 sign:" + result15[1]);
                signData = result15[1];
            } else {
                zLogAppend("SM3 sign error" + result15[0]);
            }

            String[] result16 =
                    mSafetyCardMT2.SM2VerifyWithPubKey("01", pubKey, signData, hashData);
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("验签 ‘01’：数据需要卡内再次HASH: 成功" + result16[1]);
            } else {
                zLogAppend("验签 ‘01’：数据需要卡内再次HASH" + result16[0]);
            }

            String[] result18 = mSafetyCardMT2.importSM2PubKeyByDBA("0001", SM2Cipher);
            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("DBA密钥加密导入SM2公钥 :" + result18[1]);
            } else {
                zLogAppend("DBA密钥加密导入SM2公钥 error" + result18[0]);
            }

            String[] result17 = mSafetyCardMT2.exportSM2PubKeyByDBA("0000", "020102030205");
            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
                zLogAppend("明文导出多条SM2公钥 :" + result17[1]);
                SM2Plain = result17[1].substring(2);
            } else {
                zLogAppend("明文导出多条SM2公钥 error" + result17[0]);
            }

            String[] result19 = mSafetyCardMT2.importSM2PubKeyByDBA("0000", SM2Plain);
            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result19[0])) {
                zLogAppend("明文导入SM2公钥 :" + result19[1]);
            } else {
                zLogAppend("明文导入SM2公钥 error" + result19[0]);
            }

            String[] result20 = mSafetyCardMT2.exportSM2PubKeyByDBA("0000", "020102030205");
            if (result20[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result20[0])) {
                zLogAppend("明文导出多条SM2公钥 :" + result20[1]);
                if (SM2PubKey.equals(result20[1])) {
                    zLogAppend("明文导出多条SM2公钥 成功:");
                }
            } else {
                zLogAppend("明文导出多条SM2公钥 error" + result20[0]);
            }

            String[] result21 = mSafetyCardMT2.clearMultipleDBAKey("FFFF");
            if (result21[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result21[0])) {
                zLogAppend("清除所有DBA密钥 :" + result21[1]);
            } else {
                zLogAppend("清除所有DBA密钥 error" + result21[0]);
            }
        } catch (Exception e) {
        }
    }

    private void safety_house() {

        String pubKey =
                "B9766242AF810574D9CF60B5D0A92B0D426E0E9B34F9A575ACAA64FD559330AA72D436A2C4BD2D71EF020520E650C721D63E6D1CB873FBD9C3E2712DC5E26E0B";
        String priKey = "8C96B7EB36950B97F3A77152030F2E216B87FC87E1971CB8AF7694858CA81E64";

        try {

            String[] result =
                    mSafetyCardMT2.singlePointEncryptFirstStep(pubKey, "0001", "0201", "0203");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("单点加密生成会话密钥（第一步） : 成功" + result[1]);
            } else {
                zLog("单点加密生成会话密钥（第一步） error" + result[0]);
            }

            String hp = result[1].substring(0, 32);
            Log.d(TAG, "hp= " + hp);
            String h2 = result[1].substring(32, 256);
            Log.d(TAG, "h2= " + h2);
            String h1 = result[1].substring(256, 480);
            Log.d(TAG, "h1= " + h1);
            String s = result[1].substring(480, 704);
            Log.d(TAG, "s= " + s);

            String data = "112233445566778899AABBCCDDEEFF00";

            String[] result1 = mSafetyCardMT2.importSessionKey(1, "02", hp.toUpperCase());
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("导入会话密钥 00 : 成功" + result1[1]);
            } else {
                zLogAppend("导入会话密钥 00 error" + result1[0]);
            }

            String[] result2 = mSafetyCardMT2.sessionKeyEncECB("00", "00000000", data);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("SM4加密 00 : 成功" + result2[1]);
            } else {
                zLogAppend("SM4加密 00 error" + result2[0]);
            }

            String M = result2[1];

            String B = M + h1 + h2 + s;
            Log.d(TAG, "B= " + B);
            String[] result3 = mSafetyCardMT2.digestCal("00", "03", B.substring(0, B.length() / 2));
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("SM3 首块 : 成功" + result3[1]);
            } else {
                zLogAppend("SM3 error" + result3[0]);
            }
            String[] result4 =
                    mSafetyCardMT2.digestCal("03", "03", B.substring(B.length() / 2, B.length()));
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("SM3 最后一块 : 成功" + result4[1]);
            } else {
                zLogAppend("SM3 error" + result4[0]);
            }

            String Z = result4[1];

            String[] result5 = mSafetyCardMT2.singlePointEncryptSecondStep("0202", Z, "01");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("单点加密生成会话密钥（第二步） : 成功" + result5[1]);
            } else {
                zLogAppend("单点加密生成会话密钥（第二步） error" + result5[0]);
            }

            String Q = result5[1];
            Log.d(TAG, "Q= " + Q);

            String[] result8 = mSafetyCardMT2.exportSM2PublicKey("0201");
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("导出公钥 0202 : 成功" + result8[1]);
            } else {
                zLogAppend("导出公钥 0202  error" + result8[0]);
            }

            String pubKey1 = result8[1].substring(4, 132);
            Log.d(TAG, "pubKey1= " + pubKey1);
            String[] result6 = mSafetyCardMT2.singlePointDecryptFirstStep(pubKey1, Z, Q, "01");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("单点解密获取会话密钥 （第一步） : 成功" + result6[1]);
            } else {
                zLogAppend("单点解密获取会话密钥 （第一步） error" + result6[0]);
            }
            String[] result7 = mSafetyCardMT2.singlePointDecryptSecondStep("0204", h2, "0001");
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("单点解密获取会话密钥 （第二步） : 成功" + result7[1]);
            } else {
                zLogAppend("单点解密获取会话密钥 （第二步） error" + result7[0]);
            }

            String GroupKey = "88776655443322111122334455667788";

            String[] result9 = mSafetyCardMT2.SM2PublicKeyEnc("0203", GroupKey);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("SM2加密 : " + result9[1]);
            } else {
                zLogAppend("SM2加密 error" + result9[0]);
            }

            String GroupKeyCrypto = result9[1];
            String[] result10 = mSafetyCardMT2.groupEncrypt("0204", GroupKeyCrypto, "0001");
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("群组加密获取会话密钥 :" + result10[1]);
            } else {
                zLogAppend("群组加密获取会话密钥 error" + result10[0]);
            }

            String H1 = result10[1].substring(0, 32);
            String H = result10[1].substring(32, 64);

            String[] result11 = mSafetyCardMT2.groupDecrypt(H, "0204", GroupKeyCrypto, "0001");
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("群组解密获取会话密钥 :" + result11[1]);
            } else {
                zLogAppend("群组解密获取会话密钥 error" + result11[0]);
            }

            if (H1.equalsIgnoreCase(result11[1])) {
                zLogAppend("Group Encrypt&Decrypt 测试通过！");
            }

            String[] result12 = mSafetyCardMT2.createDBAKeyFile(10);
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("创建DBA密钥文件 : 成功" + result12[1]);
            } else {
                zLogAppend("创建DBA密钥文件 error" + result12[0]);
            }

            String DBAKEY1 = "1111111111111111111111111111111111111111111111111111111111111111";
            String DBAKEY2 = "2222222222222222222222222222222222222222222222222222222222222222";
            String DBAKEY3 = "3333333333333333333333333333333333333333333333333333333333333333";
            String DBAKEY4 = "4444444444444444444444444444444444444444444444444444444444444444";

            String plain =
                    "0001" + DBAKEY1 + "0002" + DBAKEY2 + "0003" + DBAKEY3 + "0004" + DBAKEY4;
            //            String plain = "0001" + DBAKEY1 + "0002" + DBAKEY2 ;

            String[] result14 = mSafetyCardMT2.SM2PublicKeyEnc("0203", plain);
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("SM2加密 : " + result14[1]);
            } else {
                zLogAppend("SM2加密 error" + result14[0]);
            }

            String cipher = result14[1];

            String[] result15 = mSafetyCardMT2.importMultipleDBAKey("0204", cipher);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("指定SM2公钥加密导入多条DBA密钥 : " + result15[1]);
            } else {
                zLogAppend("指定SM2公钥加密导入多条DBA密钥 error" + result15[0]);
            }

            //            String[] result13 = mSafetyCardMT2.exportMultipleDBAKey(pubKey, "000100020003");
            String[] result13 = mSafetyCardMT2.exportMultipleDBAKey(pubKey, "00010002");
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("指定SM2公钥加密导出多条DBA密钥 : " + result13[1]);
            } else {
                zLogAppend("指定SM2公钥加密导出多条DBA密钥 error" + result13[0]);
            }

            String[] result16 = mSafetyCardMT2.SM2PrivateKeyDec("0204", result13[1].substring(2));
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("SM2解密 : " + result16[1]);
            } else {
                zLogAppend("SM2解密 error" + result16[0]);
            }

            String HMACSHA1_data = "00112233445566778899AABBCCDDEEFF";

            String[] result30 = mSafetyCardMT2.HMAC("0001", "10", HMACSHA1_data);
            if (result30[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result30[0])) {
                zLogAppend("HMACSHA1 计算（唯一块） :" + result30[1]);
            } else {
                zLogAppend("HMACSHA1 计算 error" + result30[0]);
            }
            String[] result35 = mSafetyCardMT2.HMAC("0001", "20", HMACSHA1_data);
            if (result35[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result35[0])) {
                zLogAppend("HMACSHA256 计算（唯一块） :" + result35[1]);
            } else {
                zLogAppend("HMACSHA256 计算 error" + result35[0]);
            }
            String[] result36 = mSafetyCardMT2.HMAC("0001", "30", HMACSHA1_data);
            if (result36[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result36[0])) {
                zLogAppend("HMACSM3 计算（唯一块） :" + result36[1]);
            } else {
                zLogAppend("HMACSM3 计算 error" + result36[0]);
            }

            String[] result31 = mSafetyCardMT2.HMAC("0001", "11", HMACSHA1_data);
            if (result31[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result31[0])) {
                zLogAppend("HMACSHA1 计算（首块） :" + result31[1]);
            } else {
                zLogAppend("HMACSHA1 计算 error" + result31[0]);
            }

            String[] result32 = mSafetyCardMT2.HMAC("0001", "12", HMACSHA1_data);
            if (result32[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result32[0])) {
                zLogAppend("HMACSHA1 计算（中间块） :" + result32[1]);
            } else {
                zLogAppend("HMACSHA1 计算 error" + result32[0]);
            }

            String[] result33 = mSafetyCardMT2.HMAC("0001", "12", HMACSHA1_data);
            if (result33[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result33[0])) {
                zLogAppend("HMACSHA1 计算（中间块） :" + result33[1]);
            } else {
                zLogAppend("HMACSHA1 计算 error" + result33[0]);
            }

            String[] result34 = mSafetyCardMT2.HMAC("0001", "13", HMACSHA1_data);
            if (result34[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result34[0])) {
                zLogAppend("HMACSHA1 计算（尾块） :" + result34[1]);
            } else {
                zLogAppend("HMACSHA1 计算 error" + result34[0]);
            }

            data = DBAKEY3 + DBAKEY1;

            String[] result17 =
                    mSafetyCardMT2.instantMessagingEncrypt("00", pubKey, "0001", "0204", data);
            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
                zLogAppend("即时通信数据加密 : " + result17[1]);
            } else {
                zLogAppend("即时通信数据加密 error" + result17[0]);
            }

            String Rp = result17[1].substring(0, 256);

            M = result17[1].substring(256, 384);

            String Sign = result17[1].substring(384, 512);

            String[] result18 = mSafetyCardMT2.instantMessagingDecrypt("00", Rp, "0001", "0204", M);
            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("即时通信数据解密 : " + result18[1]);
            } else {
                zLogAppend("即时通信数据解密 error" + result18[0]);
            }

            if (data.equalsIgnoreCase(result18[1])) {
                zLogAppend("Instant Messaging Decrypt 测试通过！");
            }

            String[] result19 =
                    mSafetyCardMT2.instantMessagingEncrypt("01", pubKey, "0001", "0204", data);
            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result19[0])) {
                zLogAppend("即时通信数据加密 首块 : " + result19[1]);
            } else {
                zLogAppend("即时通信数据加密 首块 error" + result19[0]);
            }

            Rp = result19[1].substring(0, 256);

            String M1 = result19[1].substring(256, 384);

            String[] result20 = mSafetyCardMT2.instantMessagingEncrypt("02", "", "", "", data);
            if (result20[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result20[0])) {
                zLogAppend("即时通信数据加密 中间块 : " + result20[1]);
            } else {
                zLogAppend("即时通信数据加密 中间块 error" + result20[0]);
            }

            M1 = M1 + result20[1];

            String[] result21 = mSafetyCardMT2.instantMessagingEncrypt("03", "", "", "", data);
            if (result21[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result21[0])) {
                zLogAppend("即时通信数据加密 尾块 : " + result21[1]);
            } else {
                zLogAppend("即时通信数据加密 尾块 error" + result21[0]);
            }

            M1 = M1 + result21[1].substring(0, 128);

            Sign = result21[1].substring(128, 256);

            zLogAppend("M1 : " + M1);
            String[] result22 = mSafetyCardMT2.instantMessagingDecrypt("01", Rp, "0001", "0204",
                    M1.substring(0, 128));
            if (result22[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result22[0])) {
                zLogAppend("即时通信数据解密 首块 : " + result22[1]);
            } else {
                zLogAppend("即时通信数据解密 首块 error" + result22[0]);
            }

            String[] result23 = mSafetyCardMT2.instantMessagingDecrypt("02", "", "", "",
                    M1.substring(128, 256));
            if (result23[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result23[0])) {
                zLogAppend("即时通信数据解密 中间块 : " + result23[1]);
            } else {
                zLogAppend("即时通信数据解密 中间块 error" + result23[0]);
            }

            String[] result24 = mSafetyCardMT2.instantMessagingDecrypt("03", "", "", "",
                    M1.substring(256, 384));
            if (result24[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result24[0])) {
                zLogAppend("即时通信数据解密 尾块 : " + result24[1]);
            } else {
                zLogAppend("即时通信数据解密 尾块 error" + result24[0]);
            }

            plain = result22[1] + result23[1] + result24[1];
            zLogAppend("plain : " + plain);

            String[] result25 = mSafetyCardMT2.keyExchangeUserA(pubKey, "0204");
            if (result25[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result25[0])) {
                zLogAppend("密钥协商,用户A操作 : " + result25[1]);
            } else {
                zLogAppend("密钥协商,用户A操作 error" + result25[0]);
            }

            String Rp1 = result25[1].substring(0, 256);
            String Sign1 = result25[1].substring(256, 384);

            String[] result26 =
                    mSafetyCardMT2.keyExchangeUserB("00", pubKey, "0001", "0204", "", "");
            if (result26[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result26[0])) {
                zLogAppend("密钥协商,用户B操作 首包 : " + result26[1]);
            } else {
                zLogAppend("密钥协商,用户B操作 首包 error" + result26[0]);
            }

            String[] result27 = mSafetyCardMT2.keyExchangeUserB("01", "", "", "", Rp1, Sign1);
            if (result27[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result27[0])) {
                zLogAppend("密钥协商,用户B操作 尾包 : " + result27[1]);
            } else {
                zLogAppend("密钥协商,用户B操作 尾包 error" + result27[0]);
            }
        } catch (Exception e) {

        }
    }

    private void rsa() {
        try {

            String miwen = "";
            String miwen1280 = "";
            String data = "12345678";
            String hashData = "";
            String signData = "";

            beginTime();
            String[] result = mSafetyCardMT2.createRSAPubkeyFile("0301", "0400");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("创建RSA1024公钥文件FID=0301(用于生成公私钥对) : 成功" + result[1]);
            } else {
                zLog("创建RSA1024公钥文件FID=0301(用于生成公私钥对) error" + result[0]);
            }
            zLogAppend("创建RSA1024公钥文件FID=0301 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result1 = mSafetyCardMT2.createRSAPrikeyFile("0302", "0400");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("创建RSA1024私钥文件FID=0302(用于生成公私钥对) : 成功" + result1[1]);
            } else {
                zLogAppend("创建RSA1024私钥文件FID=0302(用于生成公私钥对) error" + result1[0]);
            }
            zLogAppend("创建RSA1024私钥文件FID=0302 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result2 = mSafetyCardMT2.createRSAPubkeyFile("0303", "0400");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("创建RSA1024公钥文件FID=0303(用于导入公私钥对) : 成功" + result2[1]);
            } else {
                zLogAppend("创建RSA1024公钥文件FID=0303(用于导入公私钥对) error" + result2[0]);
            }
            zLogAppend("创建RSA1024公钥文件FID=0303 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result3 = mSafetyCardMT2.createRSAPrikeyFile("0304", "0400");
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("创建RSA1024私钥文件FID=0304(用于导入公私钥对) : 成功" + result3[1]);
            } else {
                zLogAppend("创建RSA1024私钥文件FID=0304(用于导入公私钥对) error" + result3[0]);
            }
            zLogAppend("创建RSA1024私钥文件FID=0304 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result20 = mSafetyCardMT2.createRSAPubkeyFile("0305", "0400");
            if (result20[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result20[0])) {
                zLogAppend("创建RSA1024公钥文件FID=0305(用于导入公私钥对) : 成功" + result20[1]);
            } else {
                zLogAppend("创建RSA1024公钥文件FID=0305(用于导入公私钥对) error" + result20[0]);
            }
            zLogAppend("创建RSA1024公钥文件FID=0305 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result21 = mSafetyCardMT2.createRSAPrikeyFile("0306", "0400");
            if (result21[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result21[0])) {
                zLogAppend("创建RSA1024私钥文件FID=0306(用于导入公私钥对) : 成功" + result21[1]);
            } else {
                zLogAppend("创建RSA1024私钥文件FID=0306(用于导入公私钥对) error" + result21[0]);
            }
            zLogAppend("创建RSA1024私钥文件FID=0306 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result4 = mSafetyCardMT2.createRSAPubkeyFile("0401", "0800");
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("创建RSA2048公钥文件FID=0401 : 成功" + result4[1]);
            } else {
                zLogAppend("创建RSA2048公钥文件FID=0401 error" + result4[0]);
            }
            zLogAppend("创建RSA2048公钥文件FID=0401 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result5 = mSafetyCardMT2.createRSAPrikeyFile("0402", "0800");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("创建RSA2048私钥文件FID=0402 : 成功" + result5[1]);
            } else {
                zLogAppend("创建RSA2048私钥文件FID=0402 error" + result5[0]);
            }
            zLogAppend("创建RSA2048私钥文件FID=0402 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result6 = mSafetyCardMT2.generateRSAKey("00", "01", "0301", "0302");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("产生RSA1024密钥对 FID=0301 0302 : 成功" + result6[1]);
            } else {
                zLogAppend("产生RSA1024密钥对 FID=0301 0302 error" + result6[0]);
            }
            zLogAppend("产生RSA1024密钥对 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result7 = mSafetyCardMT2.generateRSAKey("02", "01", "0401", "0402");
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("产生RSA2048密钥对 FID=0401 0402 : 成功" + result7[1]);
            } else {
                zLogAppend("产生RSA2048密钥对 FID=0401 0402 error" + result7[0]);
            }
            zLogAppend("产生RSA2048密钥对 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result8 = mSafetyCardMT2.RSAPublicKeyEnc("40", "00", "0301", data);
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("RSA1024 加密 :" + result8[1]);
                miwen = result8[1];
            } else {
                zLogAppend("RSA1024 加密 error" + result8[0]);
            }
            zLogAppend("RSA1024 加密 " + endTimeA());
            zLogAppend("");

            //            String[] result9 = mSafetyCardMT2.RSAPublicKeyEnc("40", "01", "0301", data);
            //            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
            //                zLogAppend("RSA1280 加密 : 成功" + result9[1]);
            //                miwen1280 = result9[1];
            //            } else {
            //                zLogAppend("RSA1280 加密 error" + result9[0]);
            //            }
            beginTime();
            String[] result10 = mSafetyCardMT2.RSAPrivateKeyDec("40", "00", "0302", miwen);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("RSA1024 解密 : 成功" + result10[1]);
            } else {
                zLogAppend("RSA1024 解密 error" + result10[0]);
            }
            zLogAppend("RSA1024 解密 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result11 = mSafetyCardMT2.digestCal("01", "01", data);
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("SHA-1 摘要:" + result11[1]);
                hashData = result11[1];
            } else {
                zLogAppend("SHA-1 摘要 error" + result11[0]);
            }
            zLogAppend("SHA-1 摘要 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result12 = mSafetyCardMT2.RSAPrivateKeySign("40", "80", "0302", hashData);
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("RSA1024 签名 :" + result12[1]);
                signData = result12[1];
            } else {
                zLogAppend("RSA1024 签名 error" + result12[0]);
            }
            zLogAppend("RSA1024 签名 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result13 =
                    mSafetyCardMT2.RSAPublicKeyVerify("40", "80", "0301", hashData, signData);
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("RSA1024 验签 : 成功" + result13[1]);
            } else {
                zLogAppend("RSA1024 验签 error" + result13[0]);
            }
            zLogAppend("RSA1024 验签 " + endTimeA());
            zLogAppend("");

            zLogAppend("");

            zLogAppend("↓↓↓↓↓RSA1024 导入公私钥运算↓↓↓↓↓");

            zLogAppend("");

            String exRsaPubKey1024 =
                    "C166AC3ADE54D840DE647D2BC8BF2E07981C60985DA66698FBA6C38CC686A8186FC7E1E39BB5E942C7810AA39D51E84950AB2E3B3CEF1C3B7D4548CCB45D24F76EA45461C91D3C4F22EEED728A910C786A16ABE7297B7CFBEA52EC1BCD16C84591F862E3F659CADCA9E4F678C31D19EF519A7B2947FCAD75F4FA2A2363BA033F";
            String exRsaPriKey1024 =
                    "97DD8DC4B42D1F9AE0873C1B1389BC154E8689FB5B1E7D5607D5CD9C4F9011930EC38047804FFA18EC1C1244A4165B36A6D7A477F3C3370227BE2E0A405F1BD4A9DFEDCFD1DD91953C95321B6784A16168F8B11E7FE2EC283A7B6D2C1D97FA5132215E876A64E927B507AEEE60087E59655323EC884E84A471814D66A98AB191";

            beginTime();
            String[] result14 = mSafetyCardMT2.importRSAPubKey("00", "0303", exRsaPubKey1024);
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("导入RSA1024 公钥  : 成功" + result14[1]);
            } else {
                zLogAppend("导入RSA1024 公钥  error" + result14[0]);
            }
            zLogAppend("导入RSA1024 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result15 = mSafetyCardMT2.importRSAPriKey("00", "D", "0304", exRsaPriKey1024);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("导入RSA1024 私钥D : 成功" + result15[1]);
            } else {
                zLogAppend("导入RSA1024 私钥D error" + result15[0]);
            }
            zLogAppend("导入RSA1024 私钥D " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result16 = mSafetyCardMT2.importRSAPriKey("00", "N", "0304", exRsaPubKey1024);
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("导入RSA1024 私钥N : 成功" + result16[1]);
            } else {
                zLogAppend("导入RSA1024 私钥N error" + result16[0]);
            }
            zLogAppend("导入RSA1024 私钥N " + endTimeA());
            zLogAppend("");

            String[] result17 = mSafetyCardMT2.RSAPublicKeyEnc("40", "00", "0303", data);
            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
                zLogAppend("RSA1024 加密 : 成功" + result17[1]);
                miwen = result17[1];
            } else {
                zLogAppend("RSA1024 加密 error" + result17[0]);
            }

            String[] result18 = mSafetyCardMT2.RSAPrivateKeyDec("40", "00", "0304", miwen);
            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("RSA1024 解密 : 成功" + result18[1]);
            } else {
                zLogAppend("RSA1024 解密 error" + result18[0]);
            }

            String[] result19 = mSafetyCardMT2.exportPublicKey("0303", "00", "01");
            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("导出RSA1024 公钥 :" + result19[1]);
            } else {
                zLogAppend("导出RSA1024 公钥 error" + result19[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void SymmKey() {
        try {

            String miwen = "";

            beginTime();
            String[] result1 = mSafetyCardMT2.createSymmKeyFile(10);
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLog("创建对称密钥文件 : 成功" + result1[1]);
            } else {
                zLog("创建对称密钥文件 error" + result1[0]);
            }
            zLogAppend("创建对称密钥文件 10个 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result2 = mSafetyCardMT2.importSymmKey((byte) 0x02, (byte) 0x01,
                    "414446312D49544B414446312D49544C");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("明文导入对称密钥 01 : 成功" + result2[1]);
            } else {
                zLogAppend("明文导入对称密钥 error" + result2[0]);
            }
            zLogAppend("明文导入对称密钥 01 " + endTimeA());
            zLogAppend("");

            String[] result28 = mSafetyCardMT2.importSymmKey((byte) 0x02, (byte) 0x02,
                    "414446312D49544B414446312D49544B");
            if (result28[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result28[0])) {
                zLogAppend("明文导入对称密钥 02 : 成功" + result28[1]);
            } else {
                zLogAppend("明文导入对称密钥 error" + result28[0]);
            }
            String[] result8 = mSafetyCardMT2.importSymmKey((byte) 0x02, (byte) 0x03,
                    "414446312D49544B414446312D49545A");
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("明文导入对称密钥 03 : 成功" + result8[1]);
            } else {
                zLogAppend("明文导入对称密钥 error" + result8[0]);
            }

            beginTime();
            String[] result3 = mSafetyCardMT2.exportSessionBySymm(2, (byte) 0x00, (byte) 0x02);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("使用对称密钥导出会话密钥 : 成功" + result3[1]);
                miwen = result3[1].substring(4);
            } else {
                zLogAppend("使用对称密钥导出会话密钥 error" + result3[0]);
            }
            zLogAppend("使用对称密钥导出会话密钥 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result4 = mSafetyCardMT2.importSessionBySymm(2, "05", (byte) 0x02, miwen);
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("使用对称密钥导入会话密钥 : 成功" + result4[1]);
                miwen = "";
            } else {
                zLogAppend("使用对称密钥导入会话密钥 error" + result4[0]);
            }
            zLogAppend("使用对称密钥导入会话密钥 " + endTimeA());
            zLogAppend("");

            String[] result5 = mSafetyCardMT2.exportSessionKey(4, "02");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("导出会话密钥:" + result5[1]);
            } else {
                zLogAppend("导出会话密钥 error" + result5[0]);
            }

            beginTime();
            String[] result6 = mSafetyCardMT2.exportSymmetricKey((byte) 0x05, 3, "", "0201");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("非对称密钥加密导出 对称密钥 3:" + result6[1]);
                miwen = "";
                miwen = result6[1].substring(6);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result6[0]);
            }
            zLogAppend("非对称密钥加密导出 对称密钥 3 " + endTimeA());
            zLogAppend("");

            String[] result7 = mSafetyCardMT2.SM2PrivateKeyDec("0202", miwen);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("SM2 解密:" + result7[1]);
            } else {
                zLogAppend("SM2 解密" + result7[0]);
            }

            beginTime();
            String[] result10 =
                    mSafetyCardMT2.importSymmetricKey((byte) 0x05, 4, "02", "", "0202", miwen);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("非对称密钥加密导入 对称密钥 4:" + result10[1]);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result10[0]);
            }
            zLogAppend("非对称密钥加密导入 对称密钥 4 " + endTimeA());
            zLogAppend("");

            String[] result9 = mSafetyCardMT2.exportSymmetricKey((byte) 0x00, 3, "0002", "0201");
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("对称密钥加密导出 对称密钥 3:");
                miwen = "";
                miwen = result9[1].substring(6);
                zLogAppend("miwen：" + miwen);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result9[0]);
            }

            String[] result11 =
                    mSafetyCardMT2.importSymmetricKey((byte) 0x00, 5, "02", "0002", "0202", miwen);
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("对称密钥加密导入 对称密钥 5:" + result11[1]);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result11[0]);
            }

            String[] result12 = mSafetyCardMT2.exportSymmetricKey((byte) 0x05, 4, "", "0201");
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("非对称密钥加密导出 对称密钥 4:" + result12[1]);
                miwen = "";
                miwen = result12[1].substring(6);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result12[0]);
            }

            String[] result13 = mSafetyCardMT2.SM2PrivateKeyDec("0202", miwen);
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("SM2 解密:" + result13[1]);
            } else {
                zLogAppend("SM2 解密" + result13[0]);
            }

            String[] result14 = mSafetyCardMT2.exportSymmetricKey((byte) 0x05, 5, "", "0201");
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("非对称密钥加密导出 对称密钥 5:" + result14[1]);
                miwen = "";
                miwen = result14[1].substring(6);
            } else {
                zLogAppend("非对称密钥加密导出 对称密钥" + result14[0]);
            }

            String[] result15 = mSafetyCardMT2.SM2PrivateKeyDec("0202", miwen);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("SM2 解密:" + result15[1]);
            } else {
                zLogAppend("SM2 解密" + result15[0]);
            }

            beginTime();
            String[] result16 =
                    mSafetyCardMT2.exportPublicKeyBySymmetricKey((byte) 0x02, 3, "0201");
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("使用对称密钥3 加密导出 SM2公钥 0201:" + result16[1]);
                miwen = "";
                miwen = result16[1].substring(4);
            } else {
                zLogAppend("使用对称密钥3 加密导出 SM2公钥 0201 error" + result16[0]);
            }
            zLogAppend("使用对称密钥3 加密导出 SM2公钥 0201 " + endTimeA());
            zLogAppend("");

            String SM2PubKeyCipher =
                    "4B8E5EC717F36F3886D20C558499E74E973A18B490AB13B7662C0041039D9ADDE93BC85FD95F1C81BE20A76ABB1FA689D3CB5291C0712986C384231606350DCE";

            beginTime();
            String[] result17 = mSafetyCardMT2.importSM2KeyBySymmetricKey((byte) 0x00, 3, "0205",
                    SM2PubKeyCipher);
            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
                zLogAppend("使用对称密钥3 加密导入 SM2公钥 0205:" + result17[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导入 SM2公钥 0205 error" + result17[0]);
            }
            zLogAppend("使用对称密钥3 加密导入 SM2公钥 0205 " + endTimeA());
            zLogAppend("");

            String SM2PriKeyCipher =
                    "F5888AF4C132CEA78DBD24563A63FD1C7BEA3D5A69007D1D4101BBE68C8AA0C9";

            beginTime();
            String[] result19 = mSafetyCardMT2.importSM2KeyBySymmetricKey((byte) 0x04, 3, "0206",
                    SM2PriKeyCipher);
            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result19[0])) {
                zLogAppend("使用对称密钥3 加密导入 SM2私钥 0206:" + result19[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导入 SM2私钥 0206 error" + result19[0]);
            }
            zLogAppend("使用对称密钥3 加密导入 SM2私钥 0206 " + endTimeA());
            zLogAppend("");

            String[] result18 = mSafetyCardMT2.exportPublicKey("0205", "02", "00");
            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("SM2 导出公钥 0205:" + result18[1]);
            } else {
                zLogAppend("SM2 导出公钥 0205" + result18[0]);
            }

            String[] result20 =
                    mSafetyCardMT2.SM2PublicKeyEnc("0205", "0011223344556677889988AABBCCDDEE");
            if (result20[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result20[0])) {
                zLogAppend("SM2公钥 0205 加密:" + result20[1]);
                miwen = "";
                miwen = result20[1];
            } else {
                zLogAppend("SM2公钥 0205 加密" + result20[0]);
            }

            String[] result21 = mSafetyCardMT2.SM2PrivateKeyDec("0206", miwen.toUpperCase());
            if (result21[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result21[0])) {
                zLogAppend("SM2私钥 0206 解密:" + result21[1]);
            } else {
                zLogAppend("SM2私钥 0206 解密" + result21[0]);
            }

            beginTime();
            String[] result22 =
                    mSafetyCardMT2.exportPublicKeyBySymmetricKey((byte) 0x00, 3, "0301");
            if (result22[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result22[0])) {
                zLogAppend("使用对称密钥3 加密导出 RSA1024公钥 0301:" + result22[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导出 RSA1024公钥 0301" + result22[0]);
            }

            zLogAppend("使用对称密钥3 加密导出 RSA1024公钥 0301 " + endTimeA());
            zLogAppend("");

            //            String exRsaPubKey1024 = "C166AC3ADE54D840DE647D2BC8BF2E07981C60985DA66698FBA6C38CC686A8186FC7E1E39BB5E942C7810AA39D51E84950AB2E3B3CEF1C3B7D4548CCB45D24F76EA45461C91D3C4F22EEED728A910C786A16ABE7297B7CFBEA52EC1BCD16C84591F862E3F659CADCA9E4F678C31D19EF519A7B2947FCAD75F4FA2A2363BA033F";
            //            String exRsaPriKey1024 = "97DD8DC4B42D1F9AE0873C1B1389BC154E8689FB5B1E7D5607D5CD9C4F9011930EC38047804FFA18EC1C1244A4165B36A6D7A477F3C3370227BE2E0A405F1BD4A9DFEDCFD1DD91953C95321B6784A16168F8B11E7FE2EC283A7B6D2C1D97FA5132215E876A64E927B507AEEE60087E59655323EC884E84A471814D66A98AB191";

            String exRsaPubKey1024n =
                    "32378EB9EA8B260CDF50B6A31ED6F0E7B9BFFFE286AA93E38DCF7E13B92DC920755E6DF65C21603A450E3CC0B47FE4FD2B8BFF2E45BC44D1A49474143360C3C89116B357813F18D6C31B78A63262D8A09F3B35F9E2F1C141C040172B0E296FF13DBDFF9B67196CB02714A5647DF97E2102168E8DAD808447F888FB8780C839F7";
            String exRsaPriKey1024d =
                    "757901401A6986FF08A4B030F67D810033EF3DE36CC390B309ED65F2449EF578C8115CD742D117E90DAB0FCB0F920C68D17675CA40F14E77CE71C620D7C5ED4CB508D395B468C3AA32F464C4B9BC7B9300CAE82A622B230499DFD9FC549A5EA06098F8C04594B922C4B04225F7F15D1E094461850024C27A050807B21DD8A58F";

            beginTime();
            String[] result23 = mSafetyCardMT2.importRSAPubKeyBySymmetricKey((byte) 0x00, 3, "0305",
                    exRsaPubKey1024n);
            if (result23[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result23[0])) {
                zLogAppend("使用对称密钥3 加密导入 RSA1024公钥 0305:" + result23[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导入 RSA1024公钥 0305" + result23[0]);
            }
            zLogAppend("使用对称密钥3 加密导入 RSA1024公钥 0305 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result25 =
                    mSafetyCardMT2.importRSAPriKeyBySymmetricKey((byte) 0x00, 3, "D", "0306",
                            exRsaPriKey1024d);
            if (result25[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result25[0])) {
                zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 d:" + result25[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 d" + result25[0]);
            }
            zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 d " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result24 =
                    mSafetyCardMT2.importRSAPriKeyBySymmetricKey((byte) 0x00, 3, "N", "0306",
                            exRsaPubKey1024n);
            if (result24[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result24[0])) {
                zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 n:" + result24[1]);
            } else {
                zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 n" + result24[0]);
            }
            zLogAppend("使用对称密钥3 加密导入 RSA1024私钥 0306 n " + endTimeA());
            zLogAppend("");

            String data = "12345678";

            String[] result26 = mSafetyCardMT2.RSAPublicKeyEnc("40", "00", "0305", data);
            if (result26[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result26[0])) {
                zLogAppend("RSA1024 加密 0305 : 成功" + result26[1]);
                miwen = result26[1];
            } else {
                zLogAppend("RSA1024 加密 0305 error" + result26[0]);
            }

            String[] result27 = mSafetyCardMT2.RSAPrivateKeyDec("40", "00", "0306", miwen);
            if (result27[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result27[0])) {
                zLogAppend("RSA1024 解密 0306 : 成功" + result27[1]);
            } else {
                zLogAppend("RSA1024 解密 0306 error" + result27[0]);
            }

            long t = System.currentTimeMillis();

            String[] result29 = mSafetyCardMT2.DynamicPassword("01", "03", "06",
                    "1234567890ABCDEF1234567890ABCDEF", t, 1234, "5678".toCharArray());
            if (result29[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result29[0])) {
                zLogAppend("DynamicPassword SM3: 成功" + (result29[1]));
            } else {
                zLogAppend("DynamicPassword error" + result29[0]);
            }
            t = System.currentTimeMillis();
            String[] result30 = mSafetyCardMT2.DynamicPassword("00", "04", "06", "0002", t, 1234,
                    "5678".toCharArray());
            if (result30[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result30[0])) {
                zLogAppend("DynamicPassword SM4: 成功" + (result30[1]));
            } else {
                zLogAppend("DynamicPassword error" + result30[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void sm2() {

        String miwen = "";
        String data = "12345678";
        String hashData = "";
        String signData = "";

        try {

            beginTime();
            String[] result1 = mSafetyCardMT2.createSM2PubkeyFile("0201");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLog("创建SM2公钥文件FID=0201(用于生成公私钥对): 成功" + result1[1]);
            } else {
                zLog("创建SM2公钥文件FID=0201(用于生成公私钥对)" + result1[0]);
            }
            zLogAppend("创建SM2公钥文件FID=0201 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result2 = mSafetyCardMT2.createSM2PrikeyFile("0202");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("创建SM2私钥文件FID=0202(用于生成公私钥对): 成功" + result2[1]);
            } else {
                zLogAppend("创建SM2私钥文件FID=0202(用于生成公私钥对)" + result2[0]);
            }
            zLogAppend("创建SM2私钥文件FID=0202 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result3 = mSafetyCardMT2.createSM2PubkeyFile("0203");
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("创建SM2公钥文件FID=0203(用于外部导入公钥): 成功" + result3[1]);
            } else {
                zLogAppend("创建SM2公钥文件FID=0203(用于外部导入公钥)" + result3[0]);
            }
            zLogAppend("创建SM2公钥文件FID=0203 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result4 = mSafetyCardMT2.createSM2PrikeyFile("0204");
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("创建SM2私钥文件FID=0204(用于外部导入公钥): 成功" + result4[1]);
            } else {
                zLogAppend("创建SM2私钥文件FID=0204(用于外部导入公钥)" + result4[0]);
            }
            zLogAppend("创建SM2私钥文件FID=0204 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result19 = mSafetyCardMT2.createSM2PubkeyFile("0205");
            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result19[0])) {
                zLogAppend("创建SM2公钥文件FID=0205(用于外部导入公钥): 成功" + result19[1]);
            } else {
                zLogAppend("创建SM2公钥文件FID=0205(用于外部导入公钥)" + result19[0]);
            }
            zLogAppend("创建SM2公钥文件FID=0205 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result20 = mSafetyCardMT2.createSM2PrikeyFile("0206");
            if (result20[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result20[0])) {
                zLogAppend("创建SM2私钥文件FID=0206(用于外部导入私钥): 成功" + result20[1]);
            } else {
                zLogAppend("创建SM2私钥文件FID=0206(用于外部导入私钥)" + result20[0]);
            }
            zLogAppend("创建SM2私钥文件FID=0206 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result39 = mSafetyCardMT2.createSM2PubkeyFile("0207");
            if (result39[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result39[0])) {
                zLogAppend("创建SM2公钥文件FID=0207(用于外部导入公钥 加密): 成功" + result39[1]);
            } else {
                zLogAppend("创建SM2公钥文件FID=0207(用于外部导入公钥)" + result39[0]);
            }
            zLogAppend("创建SM2公钥文件FID=0207 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result40 = mSafetyCardMT2.createSM2PrikeyFile("0208");
            if (result40[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result40[0])) {
                zLogAppend("创建SM2私钥文件FID=0208(用于外部导入私钥 加密): 成功" + result40[1]);
            } else {
                zLogAppend("创建SM2私钥文件FID=0208(用于外部导入私钥)" + result40[0]);
            }
            zLogAppend("创建SM2私钥文件FID=0208 " + endTimeA());
            zLogAppend("");

            beginTime();
            //关联创建的公私秘钥 公钥的文件标识符 私钥的文件标识符 01：导出公钥  00：不导出公钥
            String[] result5 = mSafetyCardMT2.generateSM2Key("0201", "0202", "01");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("产生SM2密钥对，并同时导出公钥:" + result5[1]);
            } else {
                zLogAppend("产生SM2密钥对，并同时导出公钥" + result5[0]);
            }
            zLogAppend("产生SM2密钥对，并同时导出公钥 " + endTimeA());
            zLogAppend("");

            beginTime();
            String str;
            str = HexUtil.strTo16("你好");
            String[] result6 = mSafetyCardMT2.SM2PublicKeyEnc("0201", str);
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("SM2 加密:" + result6[1]);
                miwen = result6[1];
            } else {
                zLogAppend("SM2 加密" + result6[0]);
            }
            zLogAppend("SM2 加密 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result7 = mSafetyCardMT2.SM2PrivateKeyDec("0202", miwen);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                // zLogAppend("SM2 解密:" + result7[1]);
                zLogAppend("SM2 解密:" + HexUtil.hexStringToString(result7[1]));
            } else {
                zLogAppend("SM2 解密" + result7[0]);
            }
            zLogAppend("SM2 解密 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result8 = mSafetyCardMT2.digestCal("01", "03", data);
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("SM3 摘要:" + result8[1]);
                hashData = result8[1];
            } else {
                zLogAppend("SM3 摘要 error" + result8[0]);
            }
            zLogAppend("SM3 摘要 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result9 = mSafetyCardMT2.SM2PrivateKeySign("0202", hashData);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("SM2 签名:" + result9[1]);
                signData = result9[1];
            } else {
                zLogAppend("SM2 签名" + result9[0]);
            }
            zLogAppend("SM2 签名 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result10 = mSafetyCardMT2.SM2PublicKeyVerify("0201", hashData, signData);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("SM2 验签: 成功" + result10[1]);
            } else {
                zLogAppend("SM2 验签" + result10[0]);
            }
            zLogAppend("SM2 验签 " + endTimeA());

            zLogAppend("");

            zLogAppend("↓↓↓↓↓SM2 导入公私钥运算↓↓↓↓↓");

            zLogAppend("");

            String pubKey =
                    "B9766242AF810574D9CF60B5D0A92B0D426E0E9B34F9A575ACAA64FD559330AA72D436A2C4BD2D71EF020520E650C721D63E6D1CB873FBD9C3E2712DC5E26E0B";
            String priKey = "8C96B7EB36950B97F3A77152030F2E216B87FC87E1971CB8AF7694858CA81E64";

            beginTime();
            String[] result11 = mSafetyCardMT2.importSM2PubKey("0203", pubKey);
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("SM2 导入公钥: 成功" + result11[1]);
            } else {
                zLogAppend("SM2 导入公钥" + result11[0]);
            }
            zLogAppend("SM2 导入公钥 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result12 = mSafetyCardMT2.importSM2PriKey("0204", priKey);
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("SM2 导入私钥: 成功" + result12[1]);
            } else {
                zLogAppend("SM2 导入私钥" + result12[0]);
            }
            zLogAppend("SM2 导入私钥 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result13 = mSafetyCardMT2.exportSM2PublicKey("0203");
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("SM2 导出公钥:" + result13[1]);
            } else {
                zLogAppend("SM2 导出公钥" + result13[0]);
            }
            zLogAppend("SM2 导出公钥 " + endTimeA());
            zLogAppend("");

            String[] result14 =
                    mSafetyCardMT2.SM2PublicKeyEnc("0203", "0011223344556677889988AABBCCDDEE");
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("SM2 加密:" + result14[1]);
                miwen = result14[1];
            } else {
                zLogAppend("SM2 加密" + result14[0]);
            }

            String[] result15 = mSafetyCardMT2.SM2PrivateKeyDec("0204", miwen);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("SM2 解密:" + result15[1]);
            } else {
                zLogAppend("SM2 解密" + result15[0]);
            }
            //
            String[] result16 = mSafetyCardMT2.digestCal("01", "03", data);
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("SM3 摘要:" + result16[1]);
                hashData = result16[1];
            } else {
                zLogAppend("SM3 摘要 error" + result16[0]);
            }

            String[] result17 = mSafetyCardMT2.SM2PrivateKeySign("0204", hashData);
            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
                zLogAppend("SM2 签名:" + result17[1]);
                signData = result17[1];
            } else {
                zLogAppend("SM2 签名" + result17[0]);
            }

            String[] result18 = mSafetyCardMT2.SM2PublicKeyVerify("0203", hashData, signData);
            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
                zLogAppend("SM2 验签: 成功" + result18[1]);
            } else {
                zLogAppend("SM2 验签" + result18[0]);
            }

            String pubKey_1 =
                    "2FB9F83762BBBC3504D1B3BF14E879766D24C01F28B4EFB6D8F9357BE31FFA3B4EFA2966EF7AC7AFFE1B3953133A10C8165BCA5A3239AE58258308F0BEF241FC";
            beginTime();
            String[] result21 = mSafetyCardMT2.importSM2PubKey("0207", pubKey_1);
            if (result21[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result21[0])) {
                zLogAppend("SM2 导入公钥 (0207): 成功" + result21[1]);
            } else {
                zLogAppend("SM2 导入公钥" + result21[0]);
            }
            zLogAppend("SM2 导入公钥 " + endTimeA());
            zLogAppend("");

            //外部用随机数s对私钥进行加密得到数据a（算法SM4 ECB）
            String a = "3D0C0E9EDED6FFB1B70B586A62BFC2FFE6ACF407C22BFF4AFF4A99087FBC90B6";
            //外部使用卡内公钥对随机数s进行加密得到数据b（算法 SM2）
            String b =
                    "EB4A149D51A7FC9276B39591E57ED3E49A7D495905F5D0EBF7A29449B62191682E0BB0247324FE40C6EB4C869620AC5E56AC3220737068CD69ADD0569C009296B882BCA93DE0DB2C26BAB6800DC89B48ED18214B9AD9AEAE6986971533736681D93B37A20EC5171A68735721E817F34B";

            String[] result22 = mSafetyCardMT2.importCipherSM2PriKey("0208", "0204", a, b);
            if (result22[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result22[0])) {
                zLogAppend("SM2 导入私钥 (0208): 成功" + result22[1]);
            } else {
                zLogAppend("SM2 导入私钥" + result22[0]);
            }
            zLogAppend("SM2 导入私钥 " + endTimeA());
            zLogAppend("");

            String[] result23 =
                    mSafetyCardMT2.SM2PublicKeyEnc("0207", "0011223344556677889988AABBCCDDEE");
            if (result23[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result23[0])) {
                zLogAppend("SM2 加密(0207):" + result23[1]);
                miwen = result23[1];
            } else {
                zLogAppend("SM2 加密" + result23[0]);
            }

            String[] result24 = mSafetyCardMT2.SM2PrivateKeyDec("0208", miwen);
            if (result24[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result24[0])) {
                zLogAppend("SM2 解密(0208):" + result15[1]);
            } else {
                zLogAppend("SM2 解密" + result15[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void digestCal() {

        try {

            //            String data = "3031300d0609608648016503040206053031300d0609608648016503040206053031300d060960864801650304020605";
            String data = "646541321676431678";

            beginTime();
            String[] result1 = mSafetyCardMT2.digestCal("01", "01", data);
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLog("SHA-1 摘要:" + result1[1]);
            } else {
                zLog("SHA-1 摘要 error" + result1[0]);
            }
            zLogAppend("SHA-1 摘要 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result2 = mSafetyCardMT2.digestCal("01", "02", data);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("SHA-256 摘要:" + result2[1]);
            } else {
                zLogAppend("SHA-256 摘要 error" + result2[0]);
            }
            zLogAppend("SHA-256 摘要 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result3 = mSafetyCardMT2.digestCal("01", "03", data);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("SM3 摘要:" + result3[1]);
            } else {
                zLogAppend("SM3 摘要 error" + result3[0]);
            }
            zLogAppend("SM3 摘要 " + endTimeA());
            zLogAppend("");
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void session_key() {

        String plainECB = "";
        String plainCBC = "";

        try {

            beginTime();
            String[] result1 = mSafetyCardMT2.exportSessionKey(0, "02");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLog("导出会话密钥: 02" + result1[1]);
            } else {
                zLog("导出会话密钥 error" + result1[0]);
            }
            zLogAppend("导出会话密钥 02 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result3 = mSafetyCardMT2.clearSessionKey(0);
            String[] result10 = mSafetyCardMT2.clearSessionKey(1);
            String[] result11 = mSafetyCardMT2.clearSessionKey(2);
            String[] result12 = mSafetyCardMT2.clearSessionKey(3);
            String[] result13 = mSafetyCardMT2.clearSessionKey(4);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("清除会话密钥 0~4: 成功" + result3[1]);
            } else {
                zLogAppend("清除会话密钥 error" + result3[0]);
            }
            zLogAppend("清除会话密钥 0~4 " + endTimeA());
            zLogAppend("");

            String[] result5 = mSafetyCardMT2.exportSessionKey(0, "02");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("导出会话密钥 00:" + result5[1]);
            } else {
                zLogAppend("导出会话密钥 error" + result5[0]);
            }

            beginTime();
            String[] result2 =
                    mSafetyCardMT2.importSessionKey(1, "02", "11223344556677889900112233445566");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("导入会话密钥 02: 成功" + result2[1]);
            } else {
                zLogAppend("导入会话密钥 error" + result2[0]);
            }
            zLogAppend("导入会话密钥 02 " + endTimeA());
            zLogAppend("");

            String[] result4 = mSafetyCardMT2.exportSessionKey(0, "02");
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("导出会话密钥:" + result4[1]);
            } else {
                zLogAppend("导出会话密钥 error" + result4[0]);
            }

            String sessionKeyMiwen = "";

            beginTime();
            String[] result14 =
                    mSafetyCardMT2.MT2ExportSessionKey((byte) 0x00, (byte) 0x02, (byte) 0x01,
                            (byte) 0x01, "0201");
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("SM2加密导出会话密钥:" + result14[1]);
                sessionKeyMiwen = result14[1].substring(4);
            } else {
                zLogAppend("SM2加密导出会话密钥 error" + result14[0]);
            }
            zLogAppend("SM2加密导出会话密钥 00 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result15 =
                    mSafetyCardMT2.MT2ImportSessionKey((byte) 0x03, (byte) 0x02, (byte) 0x01,
                            (byte) 0x01, sessionKeyMiwen, "0202");
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("SM2加密导入会话密钥:" + result15[1]);
            } else {
                zLogAppend("SM2加密导入会话密钥 error" + result15[0]);
            }
            zLogAppend("SM2加密导入会话密钥 03 " + endTimeA());
            zLogAppend("");

            String[] result16 =
                    mSafetyCardMT2.MT2ExportSessionKey((byte) 0x03, (byte) 0x02, (byte) 0x00,
                            (byte) 0x01, "0202");
            if (result16[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result16[0])) {
                zLogAppend("明文导出会话密钥:" + result16[1]);
            } else {
                zLogAppend("明文导出会话密钥 error" + result16[0]);
            }
            //            String[] result17 = mSafetyCardMT2.MT2ExportSessionKey((byte) 0x04, (byte) 0x02, (byte) 0x00, (byte) 0x01, "0202");
            //            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
            //                zLogAppend("明文导出会话密钥:" + result17[1]);
            //            } else {
            //                zLogAppend("明文导出会话密钥 error" + result17[0]);
            //            }

            beginTime();
            String[] result6 = mSafetyCardMT2.sessionKeyEncECB("00", "00000000",
                    "112233445566778899AABBCCDDEEFF00");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("会话秘钥加密 ECB:" + result6[1]);
                plainECB = result6[1];
            } else {
                zLogAppend("会话秘钥加密 ECB error" + result6[0]);
            }
            zLogAppend("会话秘钥加密 ECB " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result7 = mSafetyCardMT2.sessionKeyDecECB("00", "00000000", plainECB);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("会话秘钥解密 ECB:" + result7[1]);
            } else {
                zLogAppend("会话秘钥解密 ECB error" + result7[0]);
            }
            zLogAppend("会话秘钥解密 ECB " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result8 = mSafetyCardMT2.sessionKeyEncCBC("00", "00000000",
                    "12345678123456780123012301230123", "112233445566778899AABBCCDDEEFF00");
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("会话秘钥加密 CBC:" + result8[1]);
                plainCBC = result8[1];
            } else {
                zLogAppend("会话秘钥加密 CBC error" + result8[0]);
            }
            zLogAppend("会话秘钥加密 CBC " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result9 = mSafetyCardMT2.sessionKeyDecCBC("00", "00000000",
                    "12345678123456780123012301230123", plainCBC);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("会话秘钥解密 CBC:" + result9[1]);
            } else {
                zLogAppend("会话秘钥解密 CBC error" + result9[0]);
            }
            zLogAppend("会话秘钥解密 CBC " + endTimeA());
            zLogAppend("");

            //            String[] result17 = mSafetyCardMT2.importSessionKey(5, "02", "414446312d49544b414446312d49545A");
            //            if (result17[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result17[0])) {
            //                zLogAppend("导入会话密钥 5:" + result17[1]);
            //            } else {
            //                zLogAppend("导入会话密钥 error" + result17[0]);
            //            }
            //
            //            String[] result18 = mSafetyCardMT2.sessionKeyDecECB("00", "00000004", "FEFA1978E521FA60B50537C0FF0F96BC");
            //            if (result18[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result18[0])) {
            //                zLogAppend("会话秘钥解密 ECB:" + result18[1]);
            //            } else {
            //                zLogAppend("会话秘钥解密 ECB error" + result18[0]);
            //            }
            //
            //            String[] result19 = mSafetyCardMT2.MT2ExportSessionKey((byte) 0x04, (byte) 0x02, (byte) 0x00, (byte) 0x01, "0202");
            //            if (result19[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result19[0])) {
            //                zLogAppend("明文导出会话密钥:" + result19[1]);
            //            } else {
            //                zLogAppend("明文导出会话密钥 error" + result19[0]);
            //            }

        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void user_login() {

        try {

        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void get_challenge() {
        try {

            //sn:9000000000000001
            //SPP_MAC:5350504A2700
            //BLE_MAC:5350504A2701
            //SHA1_1:7CAD24AAC1B78EBD8BE7F08225AD56F91BB2B839 //安全屋
            //SHA1_2:8722399D037A4D0B4C17583A2DFBEFD3F848B09E //对外版
            //SHA1_3:8627CA2E1423F863A7236879D9134BE1898EFED1
            //SHA1_4:D436E0E1F6E5E8464787E1AEABE6F59E1A3C40FE
            //SHA1_5:AA0D18C0C6F1DB127015518FAB27B34EE9CCA9CC
            String[] result2 = mSafetyCardMT2.writeCardBaseInfo("00",
                    "90000000000000015350504A27005350504A27017CAD24AAC1B78EBD8BE7F08225AD56F91BB2B8398722399D037A4D0B4C17583A2DFBEFD3F848B09E8627CA2E1423F863A7236879D9134BE1898EFED1D436E0E1F6E5E8464787E1AEABE6F59E1A3C40FEAA0D18C0C6F1DB127015518FAB27B34EE9CCA9CC");
            //            String[] result2 = mSafetyCardMT2.writeCardBaseInfo("00", "90000000000000015350504A27005350504A270165D0D48C301E5B54F40D880D39AB9C7104C671AC8722399D037A4D0B4C17583A2DFBEFD3F848B09E8627CA2E1423F863A7236879D9134BE1898EFED1D436E0E1F6E5E8464787E1AEABE6F59E1A3C40FEAA0D18C0C6F1DB127015518FAB27B34EE9CCA9CC");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLog("写入卡信息 成功:" + result2[1]);
            } else {
                zLog("写入卡信息 error" + result2[0]);
            }
            String[] result3 = mSafetyCardMT2.getCardInfo("01", "08");
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("获取 SN 成功:" + result3[1]);
            } else {
                zLogAppend("获取 SN error" + result3[0]);
            }

            String[] result4 = mSafetyCardMT2.getCardInfo("02", "02");
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("获取 COS Version 成功:" + result4[1]);
            } else {
                zLogAppend("获取 COS Version error" + result4[0]);
            }
            String[] result5 = mSafetyCardMT2.getCardInfo("04", "0C");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("获取 SPP/BLE MAC 成功:" + result5[1]);
            } else {
                zLogAppend("获取 SPP/BLE MAC error" + result5[0]);
            }
            String[] result6 = mSafetyCardMT2.getCardInfo("05", "64");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("获取 SHA1 成功:" + result6[1]);
            } else {
                zLogAppend("获取 SHA1 error" + result6[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void select_file() {

        try {

            beginTime();
            String[] result = mSafetyCardMT2.getChallenge("10");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("取随机数:" + result[1]);
            } else {
                zLog("取随机数 error" + result[0]);
            }
            zLogAppend("取随机数 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result1 = mSafetyCardMT2.selectFile("04", "43534D5478303031");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("选择文件:" + result1[1]);
            } else {
                zLogAppend("选择文件 error" + result1[0]);
            }

            zLogAppend("选择文件 " + endTimeA());
            zLogAppend("");

            String[] result2 = mSafetyCardMT2.changePIN("313233343537", "313233343536");
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("修改PIN成功:" + result2[1]);
            } else {
                zLogAppend("修改PIN error" + result2[0]);
            }

            beginTime();
            String[] result6 = mSafetyCardMT2.changePIN("313233343536", "313233343536");
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("修改PIN成功:" + result6[1]);
            } else {
                zLogAppend("修改PIN error" + result6[0]);
            }
            zLogAppend("修改PIN " + endTimeA());
            zLogAppend("");

            String[] result3 = mSafetyCardMT2.verifyPIN("313233343536");
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("验证PIN成功:" + result3[1]);
            } else {
                zLogAppend("验证PIN error" + result3[0]);
            }
            String[] result5 = mSafetyCardMT2.verifyPIN("313233343537");
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("验证PIN成功:" + result5[1]);
            } else {
                zLogAppend("验证PIN error" + result5[0]);
            }

            beginTime();
            String[] result4 = mSafetyCardMT2.verifyPIN("");
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("获取重试次数 成功:" + result4[1]);
            } else {
                zLogAppend("获取重试次数 error" + result4[0]);
            }
            zLogAppend("获取重试次数 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result7 = mSafetyCardMT2.verifyPIN("313233343536");
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("验证PIN成功:" + result7[1]);
            } else {
                zLogAppend("验证PIN error" + result7[0]);
            }
            zLogAppend("验证PIN " + endTimeA());
            zLogAppend("");
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void read_binary_skf() {
        try {

            for (int i = 1; i < 32; i++) {

                String p1p2 = "EF" + FileManager.IntToByteOneHex(i).toUpperCase();
                String data = "080080F0F200FF" + FileManager.IntToByteOneHex(i).toUpperCase();

                String[] result = mSafetyCardMT2.createBinary(p1p2, data);//
                if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                    zLog("创建二进制文件 "
                            + FileManager.IntToByteOneHex(i).toUpperCase()
                            + ":"
                            + result[1]);
                } else {
                    zLog("创建二进制文件 error" + result[0]);
                    break;
                }
            }

            String[] result1 = mSafetyCardMT2.MT2readBinary(1, 0);//
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("读取二进制文件 01:" + result1[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result1[0]);
            }
            String[] result3 = mSafetyCardMT2.MT2readBinary(31, 0);//
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("读取二进制文件 31:" + result3[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result3[0]);
            }
            //            String[] result2 = mSafetyCardMT2.updateBinary(1, "00", "1122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233", false);//
            String[] result2 = mSafetyCardMT2.MT2updateBinary(1, 0, "1122334455");//
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("写二进制文件 偏移00:" + result2[1]);
            } else {
                zLogAppend("写二进制文件 error" + result2[0]);
            }
            String[] result4 = mSafetyCardMT2.MT2updateBinary(0, 40, "88990011223355448896");//
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("写二进制文件 偏移40:" + result2[1]);
            } else {
                zLogAppend("写二进制文件 error" + result2[0]);
            }

            String[] result5 = mSafetyCardMT2.MT2readBinary(0, 0);//
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("读取二进制文件 1:" + result5[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result5[0]);
            }

            String[] result6 = mSafetyCardMT2.MT2updateBinary(31, 0, "1313131313");//
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("写二进制文件 偏移00:" + result6[1]);
            } else {
                zLogAppend("写二进制文件 error" + result6[0]);
            }
            String[] result7 = mSafetyCardMT2.MT2updateBinary(0, 20, "88990011223355448896");//
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("写二进制文件 偏移00:" + result2[1]);
            } else {
                zLogAppend("写二进制文件 error" + result2[0]);
            }

            String[] result8 = mSafetyCardMT2.MT2readBinary(0, 0);//
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("读取二进制文件 31: " + result8[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result8[0]);
            }
        } catch (Exception e) {
        }
    }

    private void read_binary() {
        try {
            beginTime();
            String[] result = mSafetyCardMT2.createBinary("EF01", "080080F0F200FF01");//
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("创建二进制文件 01: 成功" + result[1]);
            } else {
                zLog("创建二进制文件 error" + result[0]);
            }
            zLogAppend("创建二进制文件 01 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result1 = mSafetyCardMT2.readBinary(1, "00", "", false);//
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("读取二进制文件 01:" + result1[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result1[0]);
            }
            zLogAppend("读取二进制文件 01 " + endTimeA());
            zLogAppend("");
            //            String[] result2 = mSafetyCardMT2.updateBinary(1, "00", "1122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233445511223344551122334455112233", false);//
            beginTime();
            String[] result2 = mSafetyCardMT2.updateBinary(1, "00", "1122334455", false);//
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("写二进制文件 01 偏移00: 成功" + result2[1]);
            } else {
                zLogAppend("写二进制文件 error" + result2[0]);
            }
            zLogAppend("写二进制文件 01 偏移00 " + endTimeA());
            zLogAppend("");
            //            String[] result10 = mSafetyCardMT2.getChallenge("08");
            //            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
            //                zLogAppend("取随机数:" + result10[1]);
            //            } else {
            //                zLogAppend("取随机数 error" + result10[0]);
            //            }
            beginTime();
            String[] result3 = mSafetyCardMT2.updateBinary(0, "40", "8877665544332211", false);//
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("写二进制文件 偏移40: 成功" + result3[1]);
            } else {
                zLogAppend("写二进制文件 error" + result3[0]);
            }
            zLogAppend("写二进制文件 01 偏移40 " + endTimeA());
            zLogAppend("");

            beginTime();
            String[] result4 = mSafetyCardMT2.readBinary(0, "00", "", false);//
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("读取二进制文件 01:" + result4[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result4[0]);
            }
            zLogAppend("读取二进制文件 01 " + endTimeA());
            zLogAppend("");

            String[] result5 = mSafetyCardMT2.createBinary("EF02", "080080F0F200FF02");//
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("创建二进制文件 02:" + result5[1]);
            } else {
                zLogAppend("创建二进制文件 02 error" + result5[0]);
            }

            String[] result7 = mSafetyCardMT2.updateBinary(2, "00", "66778899AA", false);//
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("写二进制文件 偏移00:" + result7[1]);
            } else {
                zLogAppend("写二进制文件 error" + result7[0]);
            }
            String[] result8 = mSafetyCardMT2.updateBinary(0, "40", "1122334455667788", false);//
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("写二进制文件 偏移40:" + result8[1]);
            } else {
                zLogAppend("写二进制文件 error" + result8[0]);
            }
            String[] result9 = mSafetyCardMT2.readBinary(0, "00", "", false);//
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("读取二进制文件:" + result9[1]);
            } else {
                zLogAppend("读取二进制文件 error" + result9[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void create_key() {
        try {

            String[] result = mSafetyCardMT2.createFile("ADF1",
                    "18020000F1F1FFFFFFFFFFFFFFFF43534D5478303031");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("创建ADF:" + result[1]);
            } else {
                zLog("创建ADF error" + result[0]);
            }

            String[] result1 = mSafetyCardMT2.createFile("0000", "1F10FFFFFFFFFFFF");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("创建KEY文件:" + result1[1]);
            } else {
                zLogAppend("创建KEY文件 error" + result1[0]);
            }

            String[] result2 = mSafetyCardMT2.writeKey("00", "01",
                    "F011040133436F7265536869656C644D5478303031", true);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("明文装载ADF1_MK:" + result2[1]);
            } else {
                zLogAppend("明文装载ADF1_MK error" + result2[0]);
            }

            String[] result3 = mSafetyCardMT2.writeKey("01", "01",
                    "F02104FF334144463144414D4B4144463144414D4B", true);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("明文装载DAMK (SM4):" + result3[1]);
            } else {
                zLogAppend("明文装载DAMK error" + result3[0]);
            }

            String[] result4 = mSafetyCardMT2.writeKey("01", "02",
                    "F02100FF334144463144414D4B414446314441FFFF", true);
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("明文装载DAMK (3DES):" + result4[1]);
            } else {
                zLogAppend("明文装载DAMK error" + result4[0]);
            }

            String[] result5 = mSafetyCardMT2.writeKey("02", "01",
                    "F01104FF33414446312D45544B414446312D45544B", true);
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("明文装载ETK (SM4):" + result5[1]);
            } else {
                zLogAppend("明文装载ETK error" + result5[0]);
            }

            String[] result6 = mSafetyCardMT2.writeKey("02", "02",
                    "F01100FF33414446312D45544B414446312D45FFFF", true);
            if (result6[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result6[0])) {
                zLogAppend("明文装载ETK (3DES):" + result6[1]);
            } else {
                zLogAppend("明文装载ETK error" + result6[0]);
            }

            String[] result7 = mSafetyCardMT2.writeKey("03", "01",
                    "F01104FF33414446312D49544B414446312D49544B", true);
            if (result7[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result7[0])) {
                zLogAppend("明文装载ITK (SM4):" + result7[1]);
            } else {
                zLogAppend("明文装载ITK error" + result7[0]);
            }

            String[] result8 = mSafetyCardMT2.writeKey("03", "02",
                    "F01100FF33414446312D49544B414446312D49FFFF", true);
            if (result8[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result8[0])) {
                zLogAppend("明文装载ITK (3DES):" + result8[1]);
            } else {
                zLogAppend("明文装载ITK error" + result8[0]);
            }

            String[] result9 = mSafetyCardMT2.writeKey("0A", "01",
                    "F021FF0233313233343536FFFFFFFFFFFFFFFFFFFF", true);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("明文装载PIN:" + result9[1]);
            } else {
                zLogAppend("明文装载PIN error" + result9[0]);
            }

            String[] result10 = mSafetyCardMT2.writeKey("07", "01",
                    "F01104FF33414446312D50554B414446312D50554B", true);
            if (result10[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result10[0])) {
                zLogAppend("明文装载PUK (SM4):" + result10[1]);
            } else {
                zLogAppend("明文装载PUK error" + result10[0]);
            }

            String[] result11 = mSafetyCardMT2.writeKey("07", "02",
                    "F01100FF33414446312D50554B414446312D50FFFF", true);
            if (result11[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result11[0])) {
                zLogAppend("明文装载PUK (3DES):" + result11[1]);
            } else {
                zLogAppend("明文装载PUK error" + result11[0]);
            }

            String[] result12 = mSafetyCardMT2.writeKey("08", "01",
                    "F01104FF33414446312D52504B414446312D52504B", true);
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("明文装载RPK (SM4):" + result12[1]);
            } else {
                zLogAppend("明文装载RPK error" + result12[0]);
            }

            String[] result13 = mSafetyCardMT2.writeKey("08", "02",
                    "F01100FF33414446312D52504B414446312D52FFFF", true);
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("明文装载RPK (3DES):" + result13[1]);
            } else {
                zLogAppend("明文装载RPK error" + result13[0]);
            }

            String[] result14 = mSafetyCardMT2.selectFile("00", "3F00");
            if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
                zLogAppend("选择文件MF:" + result14[1]);
            } else {
                zLogAppend("选择文件MF error" + result14[0]);
            }

            //外部认证
            byte bData[] = new byte[16];
            String[] res = mSafetyCardMT2.getChallengeA("10");
            String challenge = res[1];
            SM4 sm4 = new SM4();
            SM4_Context context = new SM4_Context();
            context.isPadding = false;
            try {
                sm4.sm4_setkey_enc(context,
                        FileManager.hexToBytes("414446312D45544B414446312D45544B"));
                bData = sm4.sm4_crypt_ecb(context, FileManager.hexToBytes(challenge));
            } catch (Exception e) {
                e.printStackTrace();
            }

            String data = FileManager.bytesToHex(bData);

            String[] result15 = mSafetyCardMT2.externalAuthentication(data);
            if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
                zLogAppend("外部认证:" + result15[1]);
                create_1121_key();
            } else {
                zLogAppend("外部认证 error" + result15[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void create_1121_key() {
        try {

            String[] result = mSafetyCardMT2.createFile("1121",
                    "18020000F1F1FFFFFFFFFFFFFFFF3131323150726F6A656374");
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLogAppend("创建1121_ADF:" + result[1]);
            } else {
                zLogAppend("创建1121_ADF error" + result[0]);
            }

            String[] result1 = mSafetyCardMT2.createFile("0000", "1F10FFF0F1FFFFFF");
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("创建KEY文件:" + result1[1]);
            } else {
                zLogAppend("创建KEY文件 error" + result1[0]);
            }

            String[] result2 = mSafetyCardMT2.writeKey("00", "01",
                    "F011040133436F7265536869656C644D5478303031", true);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("明文装载1121_ADF1_MK:" + result2[1]);
            } else {
                zLogAppend("明文装载1121_ADF1_MK error" + result2[0]);
            }

            String[] result3 = mSafetyCardMT2.writeKey("01", "01",
                    "F02104FF334144463144414D4B4144463144414D4B", true);
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLogAppend("明文装载1121_DAMK (SM4):" + result3[1]);
            } else {
                zLogAppend("明文装载1121_DAMK error" + result3[0]);
            }

            String[] result5 = mSafetyCardMT2.writeKey("02", "01",
                    "F01104FF33414446312D45544B414446312D45544B", true);
            if (result5[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result5[0])) {
                zLogAppend("明文装载1121_ETK (SM4):" + result5[1]);
            } else {
                zLogAppend("明文装载1121_ETK error" + result5[0]);
            }

            String[] result9 = mSafetyCardMT2.writeKey("0A", "01",
                    "F021FF0233313233343536FFFFFFFFFFFFFFFFFFFF", true);
            if (result9[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result9[0])) {
                zLogAppend("明文装载1121_PIN:" + result9[1]);
            } else {
                zLogAppend("明文装载1121_PIN error" + result9[0]);
            }

            String[] result12 = mSafetyCardMT2.writeKey("08", "01",
                    "F01104FF33414446312D52504B414446312D52504B", true);
            if (result12[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result12[0])) {
                zLogAppend("明文装载1121_RPK (SM4):" + result12[1]);
            } else {
                zLogAppend("明文装载1121_RPK error" + result12[0]);
            }

            String[] result13 = mSafetyCardMT2.createFile("FFFC", "120100F2F200FF11");
            if (result13[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result13[0])) {
                zLogAppend("创建1121工作密钥文件:" + result13[1]);
            } else {
                zLogAppend("创建1121工作密钥文件 error" + result13[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void create_mf() {
        try {
            String[] result3 = mSafetyCardMT2.createMF();
            if (result3[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result3[0])) {
                zLog("创建MF:" + result3[1]);
            } else {
                zLog("创建MF error" + result3[0]);
            }

            String[] result = mSafetyCardMT2.createKey();
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLogAppend("创建KEY:" + result[1]);
            } else {
                zLogAppend("创建KEY error" + result[0]);
            }

            String[] result1 = mSafetyCardMT2.writeKey("00", "01",
                    "F011040133436F7265536869656C6453414D434F53", true);
            if (result1[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result1[0])) {
                zLogAppend("明文装载MK:" + result1[1]);
            } else {
                zLogAppend("明文装载MK error" + result1[0]);
            }

            String[] result2 = mSafetyCardMT2.writeKey("01", "01",
                    "F02104FF3344414D4B44414D4B44414D4B44414D4B", true);
            if (result2[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result2[0])) {
                zLogAppend("明文装载DAMK:" + result2[1]);
            } else {
                zLogAppend("明文装载DAMK error" + result2[0]);
            }

            String[] result4 = mSafetyCardMT2.writeKey("02", "01",
                    "F011040133414446312D45544B414446312D45544B", true);
            if (result4[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result4[0])) {
                zLogAppend("明文装载ETK_DF01:" + result4[1]);
            } else {
                zLogAppend("明文装载ETK_DF01 error" + result4[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void del_mf() {
        try {
            String[] result = mSafetyCardMT2.delMF();
            if (result[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result[0])) {
                zLog("删除MF:" + result[1]);
            } else {
                zLog("删除MF error" + result[0]);
            }
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
    }

    private void sm2_sing_verify() {
    }

    private void sm4_calc() {

        new Thread() {
            public void run() {
                beginTime();
                String dataC = "";

                final String data =
                        "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00";

                String[] rec = mSafetyCardMT2.sessionKeyEncECB("01", "00000000", data);

                dataC = rec[1];
                for (int i = 0; i < 300; i++) {
                    String[] rec2 = mSafetyCardMT2.sessionKeyEncECB("02", "00000000", data);
                    if (!rec2[0].equals(SafetyCardMT2.RES_OK)) {
                        break;
                    } else {
                        dataC = dataC + rec2[1];
                    }
                }

                String[] rec1 = mSafetyCardMT2.sessionKeyEncECB("03", "00000000", data);

                dataC = dataC + rec1[1];

                endTime();
                zLogAppend("dataC:" + dataC.length());
            }

            ;
        }.start();
    }

    private void sendAPDU(String capdu) {
        try {
            String string1 = mSafetyCardMT2.sendAPDU(capdu);
            zLogAppend("recv:" + string1);
        } catch (Exception e) {
            zLog("发送异常" + e.getMessage());
        }
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
    private long mUseTime;

    public void beginTime() {
        mBeginTime = System.currentTimeMillis();
    }

    public void endTime2() {
        mEndTime = System.currentTimeMillis();
        mUseTime = mEndTime - mBeginTime;
    }

    public void endTime() {
        mEndTime = System.currentTimeMillis();
        zLogAppend("用时：" + (mEndTime - mBeginTime) + "ms");
        zLogAppend("");
    }

    public String endTimeA() {
        mEndTime = System.currentTimeMillis();
        return ("用时：" + (mEndTime - mBeginTime) + "ms");
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

    public static String bytes2Hex(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        String ret = "";
        for (int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(data[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            ret += hex.toUpperCase();
        }
        return ret;
    }

    void initCheckBox() {
        cb1.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb1Flag = true;
                } else {
                    cb1Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
        cb2.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb2Flag = true;
                } else {
                    cb2Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
        cb3.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb3Flag = true;
                } else {
                    cb3Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
        cb4.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb4Flag = true;
                } else {
                    cb4Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
        cb5.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb5Flag = true;
                } else {
                    cb5Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
        cb6.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    cb6Flag = true;
                } else {
                    cb6Flag = false;
                }
                zLog("CheckBox1:"
                        + cb1Flag
                        + "; "
                        + "CheckBox2:"
                        + cb2Flag
                        + "; "
                        + "CheckBox3:"
                        + cb3Flag
                        + "; "
                        + "CheckBox4:"
                        + cb4Flag
                        + "; "
                        + "CheckBox5:"
                        + cb5Flag
                        + "; "
                        + "CheckBox6:"
                        + cb6Flag
                        + "; ");
            }
        });
    }
}
