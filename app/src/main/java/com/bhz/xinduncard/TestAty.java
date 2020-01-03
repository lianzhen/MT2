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
import com.google.gson.Gson;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class TestAty extends AppCompatActivity {
    @BindView(R.id.btn_create_mf) Button btnCreateMf;
    @BindView(R.id.btn_delete_mf) Button btnDeleteMf;
    @BindView(R.id.btn_select_mf) Button btnCreateKey;
    @BindView(R.id.btn_select_adf) Button btnWriteKey;
    @BindView(R.id.btn_create_ADF) Button btnCreateADF;
    @BindView(R.id.btn_create_erjinzhi) Button btnCreateErjinzhi;
    @BindView(R.id.btn_read_erjinzhi) Button btnReadErjinzhi;
    @BindView(R.id.btn_write_erjinzhi) Button btnWriteErjinzhi;
    @BindView(R.id.btn_create_publicFile) Button btnCreatePublicFile;
    @BindView(R.id.btn_create_priFile) Button btnCreatePriFile;
    @BindView(R.id.btn_peiDui) Button btnPeiDui;
    @BindView(R.id.btn_SM4_file) Button btnSM4File;
    @BindView(R.id.btn_import_SM4Key) Button btnImportSM4Key;
    @BindView(R.id.btn_create_ADF2) Button btnCreateADF2;
    @BindView(R.id.btn_SM2_enc) Button btnSM2Enc;
    @BindView(R.id.btn_SM2_dec) Button btnSM2Dec;
    @BindView(R.id.btn_import_sm2PubKey) Button btnImportSm2PubKey;
    @BindView(R.id.btn_import_sm2PubKey_enc) Button btnImportSm2PubKeyEnc;
    @BindView(R.id.sha1_digest) Button sha1Digest;
    @BindView(R.id.sha256_digest) Button sha256Digest;
    @BindView(R.id.sm3_digest) Button sm3Digest;
    @BindView(R.id.btn_pri_sign) Button btnPriSign;
    @BindView(R.id.btn_pub_verify) Button btnPubVerify;
    @BindView(R.id.btn_SM2_importSM4Key) Button btnSM2ImportSM4Key;
    @BindView(R.id.btn_SM4_importSM4Key) Button btnSM4ImportSM4Key;
    @BindView(R.id.btn_importSessionKey_MingWen) Button btnImportSessionKeyMingWen;
    @BindView(R.id.btn_importSessionKey_MiWen) Button btnImportSessionKeyMiWen;
    @BindView(R.id.btn_exportSessionKey_MingWen) Button btnExportSessionKeyMingWen;
    @BindView(R.id.btn_exportSessionKey_MiWen) Button btnExportSessionKeyMiWen;
    private SafetyCardMT2 mSafetyCardMT2;
    private String TAG = "TestAty";
    //导出的公钥值
    private String tagPubKey = "";
    //SM2加密后的秘文
    private String sm2MiWen = "";
    //计算出来的摘要值
    private String digestData = "";
    //私钥加签得到的值
    private String hashData = "";
    private String offSet = "00";

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
        mSafetyCardMT2.setPrintLog(true);
    }

    @OnClick({
            R.id.btn_create_mf, R.id.btn_delete_mf, R.id.btn_select_mf, R.id.btn_select_adf,
            R.id.btn_create_ADF, R.id.btn_create_erjinzhi, R.id.btn_read_erjinzhi,
            R.id.btn_write_erjinzhi, R.id.btn_create_publicFile, R.id.btn_create_priFile,
            R.id.btn_peiDui, R.id.btn_SM4_file, R.id.btn_import_SM4Key, R.id.btn_create_ADF2,
            R.id.btn_SM2_enc, R.id.btn_SM2_dec, R.id.btn_import_sm2PubKey,
            R.id.btn_import_sm2PubKey_enc, R.id.sha1_digest, R.id.sha256_digest, R.id.sm3_digest,
            R.id.btn_pri_sign, R.id.btn_pub_verify, R.id.btn_SM2_importSM4Key,
            R.id.btn_SM4_importSM4Key, R.id.btn_importSessionKey_MingWen,
            R.id.btn_importSessionKey_MiWen, R.id.btn_exportSessionKey_MingWen,
            R.id.btn_exportSessionKey_MiWen,
    })
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_create_mf:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createMF();
                    }
                }).start();
                break;
            case R.id.btn_delete_mf:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        deleteMF();
                    }
                }).start();

                break;
            case R.id.btn_select_mf:
                //选择MF目录
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        selectFileByFId("3F00");
                    }
                }).start();

                break;
            case R.id.btn_select_adf:
                //选择ADF目录
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        selectFileByFId("ADF1");
                    }
                }).start();
                break;
            case R.id.btn_create_ADF:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createADF();
                    }
                }).start();
                break;
            case R.id.btn_create_ADF2:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createADF2();
                    }
                }).start();
                break;
            case R.id.btn_create_erjinzhi:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createBinary();
                    }
                }).start();
                break;
            case R.id.btn_read_erjinzhi:
                readBinary();
                break;
            case R.id.btn_write_erjinzhi:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        UserInfoBean userInfoBean = new UserInfoBean();
                        userInfoBean.setUserName("李安阵");
                        userInfoBean.setAge(26);
                        userInfoBean.setPhoneNumber("15330062343");
                        String userInfo = new Gson().toJson(userInfoBean);
                        Log.i(TAG, userInfo);
                        userInfo = Util.getHexString(userInfo.getBytes());
                        writeBinary(userInfo);
                    }
                }).start();

                break;
            case R.id.btn_create_publicFile:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createPubKeyFile("0270");
                        createPubKeyFile("0272");
                        createPubKeyFile("0274");
                    }
                }).start();
                break;
            case R.id.btn_create_priFile:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        createPriKeyFile("0271");
                        createPriKeyFile("0273");
                        createPriKeyFile("0275");
                    }
                }).start();
                break;
            case R.id.btn_peiDui:
                peidui();
                break;

            case R.id.btn_SM2_enc:
                sm2Enc("0270", "中午的饭不太好吃,希望厨房能够继续改善@汉王科技******$$$可好啊");
                break;
            case R.id.btn_SM2_dec:
                sm2Dec("0271", sm2MiWen,true);
                break;
            case R.id.btn_import_sm2PubKey:
                importSM2PubKey("0272", tagPubKey);
                break;
            case R.id.btn_import_sm2PubKey_enc:
                sm2Enc("0272", "中午的饭不太好吃,希望厨房能够继续改善@汉王科技******$$$可好啊!");
                break;
            case R.id.sha1_digest:
                String data =
                        "中午的饭不太好吃,希望厨房能够继续改善@汉王科技******$$$可好啊,图否让他踢日尔特子瑞特托日特的分开来给大家了开关机离开图否让他踢日尔特子瑞特托日特的分开瑞特托日特的分!";
                //转换成16进制的字符串
                data = Util.getHexString(data.getBytes());
                digest("01", data);
                break;
            case R.id.sha256_digest:
                StringBuilder builder1 = new StringBuilder();
                for (int i = 0; i < 100; i++) {
                    builder1.append("F");
                }
                digest("02", builder1.toString());
                break;
            case R.id.sm3_digest:
                String data2 = "中午的饭不太好吃,希望厨房能够继续改善@汉王科技******$$$可好啊!";
                data2 = Util.getHexString(data2.getBytes());
                digest("03", data2);
                break;
            case R.id.btn_pri_sign:
                priKeySign("0271", digestData);
                break;
            case R.id.btn_pub_verify:
                pubKeyVerify("0270", digestData, hashData);
                break;
            case R.id.btn_SM4_file:
                //创建对称秘钥的文件夹
                createSM4File(3);
                break;
            case R.id.btn_import_SM4Key:
                //明文导入对称秘钥
                importSM4Key((byte) 0x02, (byte) 0x01, "414446312D49544B414446312D49544C");
                break;
            case R.id.btn_SM2_importSM4Key:
                //SM2加密导入对称秘钥
                importSM4KeyWithSM2((byte) 0x05, (byte) 0x02, "02", "", "0202",
                        "414446312D49544B414446312D49544C");
                break;
            case R.id.btn_SM4_importSM4Key:
                //SM4加密导入对称秘钥
                importSM4KeyWithSM2((byte) 0x00, (byte) 0x03, "02", "", "",
                        "414446312D49544B414446312D49544C");
                break;
            case R.id.btn_importSessionKey_MingWen:
                //明文导入会话ID
                importSessionKeyMingW(1, "02", "10112233445566778899AABBCCDDEEFF");
                importSessionKeyMingW(2, "02", "20112233445566778899AABBCCDDEEFF");
                importSessionKeyMingW(3, "02", "30112233445566778899AABBCCDDEEFF");
                importSessionKeyMingW(4, "02", "40112233445566778899AABBCCDDEEFF");
                importSessionKeyMingW(5, "02", "50112233445566778899AABBCCDDEEFF");

                break;
            case R.id.btn_importSessionKey_MiWen:
                //使用SM2加密
                String[] encResult =
                        mSafetyCardMT2.SM2PublicKeyEnc("0270", "20112233445566778899AABBCCDDEEFF");
                if (SafetyCardMT2.RES_OK.equals(encResult[0])) {
                    //SM2加密成功
                    sm2MiWen = encResult[1];
                    Log.d(TAG, "SM2加密成功" + encResult[1]);
                    importSessionKeyMiW((byte) 0x02, (byte) 0x02, (byte) 0x01, (byte) 0x01,
                            sm2MiWen, "0271");
                } else {
                    Log.d(TAG, "SM2加密失败" + encResult[0]);
                }

                String[] encResult2 =
                        mSafetyCardMT2.SM2PublicKeyEnc("0270", "30112233445566778899AABBCCDDEEFF");
                if (SafetyCardMT2.RES_OK.equals(encResult2[0])) {
                    //SM2加密成功
                    sm2MiWen = encResult2[1];
                    Log.d(TAG, "SM2加密成功" + encResult2[1]);
                    importSessionKeyMiW((byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x01,
                            sm2MiWen, "0271");
                } else {
                    Log.d(TAG, "SM2加密失败" + encResult2[0]);
                }

                break;
            case R.id.btn_exportSessionKey_MingWen:
                exportSessionKeyWithMingW(0, "02");
                exportSessionKeyWithMingW(1, "02");
                exportSessionKeyWithMingW(2, "02");
                exportSessionKeyWithMingW(3, "02");
                exportSessionKeyWithMingW(4, "02");
                break;
            case R.id.btn_exportSessionKey_MiWen:
                exportSessionKeyWithMiW((byte) 0x02, (byte) 0x02, (byte) 0x01, (byte) 0x01, "0270");
                exportSessionKeyWithMiW((byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x01, "0270");
                break;
        }
    }

    //创建MF
    private void createMF() {
        String[] mf = mSafetyCardMT2.createMF();
        if (SafetyCardMT2.RES_OK.equals(mf[0])) {
            Log.d(TAG, "创建MF" + mf[1]);
            //创建MF文件下的key值
            createMFKey();
        } else {
            Log.d(TAG, "创建MF" + mf[0]);
        }
    }

    //删除MF
    private void deleteMF() {
        String[] delMF = mSafetyCardMT2.delMF();
        if (SafetyCardMT2.RES_OK.equals(delMF[0])) {
            Log.d(TAG, "删除MF" + delMF[1]);
        } else {
            Log.d(TAG, "删除MF" + delMF[0]);
        }
    }

    //创建MF的key文件
    private void createMFKey() {
        String[] key = mSafetyCardMT2.createKey();
        if (SafetyCardMT2.RES_OK.equals(key[0])) {
            Log.d(TAG, "创建MF_Key文件" + key[1]);
            //装载Key值
            //1.装载主控秘钥控制MF下文件的建立和密钥的写入
            writeKey("00", "01", "F0110401FF436F7265536869656C6453414D434F53", true);
            //系统维护秘钥
            writeKey("01", "01", "F02104FFFF44414D4B44414D4B44414D4B44414D4B", true);
            //外部认证的key
            writeKey("02", "01", "F0110401FF414446312D45544B414446312D45544B", true);
            //PIN认证的key
            writeKey("0A", "01", "F021FF02FF313233343536FFFFFFFFFFFFFFFFFFFF", true);
        } else {
            Log.d(TAG, "创建Key" + key[0]);
        }
    }

    //创建ADF文件
    private void createADF() {
        String[] adf1 =
                mSafetyCardMT2.createFile("ADF1", "18020000F1F1FFFFFFFFFFFFFFFF43534D5478303031");
        if (SafetyCardMT2.RES_OK.equals(adf1[0])) {
            Log.d(TAG, "ADF1创建成功>>>>>>>>>>>>>>>>>>>>>>>>>>");
            //装载key值
            createADFKey();
        } else {
            Log.d(TAG, "ADF1创建" + adf1[0]);
        }
    }

    //创建ADF的key文件
    private void createADFKey() {
        String[] key = mSafetyCardMT2.createFile("0000", "1F10FFFFFFFFFFFF");
        if (SafetyCardMT2.RES_OK.equals(key[0])) {
            Log.d(TAG, "创建ADF_Key文件" + key[1]);
            //装载Key值
            //主控秘钥-控制DF下文件的建立和秘钥的写入
            writeKey("00", "01", "F0110401FF436F7265536869656C644D5478303031", true);
            //维护秘钥key
            writeKey("01", "01", "F02104FFFF4144463144414D4B4144463144414D4B", true);
            //外部认证秘钥key
            writeKey("02", "01", "F01104FFFF414446312D45544B414446312D45544B", true);
            //PIN认证key
            writeKey("0A", "01", "F021FF02FF313233343536FFFFFFFFFFFFFFFFFFFF", true);
        } else {
            Log.d(TAG, "创建Key" + key[0]);
        }
    }

    /**
     * 装载或者更新key值
     *
     * @param keyType 00：MK_MF    主控秘钥->控制MF下文件的建立和秘钥的写入,作为默认的外部认证秘钥
     * 00: MK_DF01  主控秘钥->控制DF下文件的建立和秘钥的写入,作为默认的外部认证秘钥
     * 01: DAMK_MF  系统维护秘钥->发卡方用于产生更新二进制文件或记录命令的MAC
     * 01：DAMK_DF01 应用维护秘钥->应用提供方用于产生更新二进制文件或记录命令的MAC
     * 02：ETK_DF01  外部认证秘钥->用于载体鉴别终端身份，鉴别通过后改变应用安全状态
     * 03：ITK_DF01  内部认证秘钥->用于终端鉴别载体身份
     * 0A: PIN_DF01  鉴别密码PIN->用于载体鉴别用户身份
     * 07：PUK_DF01  PIN解锁秘钥->用于解锁PIN
     * 08：RPK_DF01  重装秘钥->用于重装PIN
     * @param keyId 01：SM4   02:3DES
     * @param isPlain true:明文装载  false：秘文装载
     */
    private void writeKey(String keyType, String keyId, String data, boolean isPlain) {
        mSafetyCardMT2.writeKey(keyType, keyId, data, isPlain);
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

    //选择目录
    private void selectFileByFId(String fileId) {
        //选择主控目录
        String[] result14 = mSafetyCardMT2.selectFile("00", fileId);
        if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
            //进行MF文件外部认证
            if ("3F00".equals(fileId)) {
                Log.d(TAG, "选择主控目录成功" + result14[1]);
                externalAuth("414446312D45544B414446312D45544B");
            } else if ("ADF1".equals(fileId)) {
                //ADF1文件的外部认证
                Log.d(TAG, "选择ADF1目录成功" + result14[1]);
                externalAuth("414446312D45544B414446312D45544B");
                //验证PIN
                pinVerify("313233343536");
            }
        } else {
            Log.d(TAG, "选择指定目录失败" + result14[1]);
        }
    }

    //创建ADF2文件
    private void createADF2() {
        String[] adf1 =
                mSafetyCardMT2.createFile("ADF2", "18020000F0F0FFFFFFFFFFFFFFFF53534D5478303031");
        if (SafetyCardMT2.RES_OK.equals(adf1[0])) {
            Log.d(TAG, "ADF2创建" + adf1[1]);
        } else {
            Log.d(TAG, "ADF2创建" + adf1[0]);
        }
    }

    //进行外部认证
    private void externalAuth(String fileName) {
        //外部认证
        byte bData[] = new byte[16];
        String[] res = mSafetyCardMT2.getChallengeA("10");
        String challenge = res[1];
        SM4 sm4 = new SM4();
        SM4_Context context = new SM4_Context();
        context.isPadding = false;
        try {
            sm4.sm4_setkey_enc(context, FileManager.hexToBytes(fileName));
            bData = sm4.sm4_crypt_ecb(context, FileManager.hexToBytes(challenge));
        } catch (Exception e) {
            e.printStackTrace();
        }

        String data = FileManager.bytesToHex(bData);

        String[] result15 = mSafetyCardMT2.externalAuthentication(data);
        if (result15[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result15[0])) {
            Log.d(TAG, "外部认证成功" + result15[1]);
        } else {
            Log.d(TAG, "外部认证失败" + result15[0]);
        }
    }

    private void pinVerify(String pin) {
        if (pin == null || "".equals(pin)) {
            return;
        }
        String[] pinResult = mSafetyCardMT2.verifyPIN(pin);
        if (SafetyCardMT2.RES_OK.equals(pinResult[0])) {
            Log.d(TAG, "PIN认证成功" + pinResult[1]);
        } else {
            Log.d(TAG, "PIN认证失败" + pinResult[0]);
        }
    }

    //创建二进制文件
    private void createBinary() {
        String[] ef01 = mSafetyCardMT2.createBinary("EF01", "080080F0F000FF01");
        if (SafetyCardMT2.RES_OK.equals(ef01[0])) {
            Log.d(TAG, "二进制文件创建" + ef01[1]);
        } else {
            Log.d(TAG, "二进制文件创建" + ef01[0]);
        }
    }

    //写二进制文件
    private void writeBinary(String data) {
        //先读取二进制文件里面的内容
        String oldData = readBinary();
        if ("".equals(oldData) || oldData == null) {
            return;
        }
        UserInfoBean userInfoBean = new Gson().fromJson(oldData, UserInfoBean.class);
        //然后开始写数据
        String[] result = mSafetyCardMT2.updateBinary(1, "00", data, false);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "写二进制文件成功: " + data.getBytes().length);
        } else {
            Log.d(TAG, "写二进制文件" + result[0]);
        }
    }

    //读二进制文件
    private String readBinary() {
        String[] result = mSafetyCardMT2.readBinary(1, "00", "", false);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            // 把十六进制的数据转化成java String
            byte b[] = Util.hexStringToBytes(result[1]);
            String data = new String(b);
            int index = data.lastIndexOf("}");
            data = data.substring(0, index + 1);
            Log.d(TAG, "读二进制文件===" + data);
            return data;
        } else {
            Log.d(TAG, "读进制文件" + result[0]);
        }
        return null;
    }

    //创建公钥文件
    private void createPubKeyFile(String fId) {
        //创建公钥文件
        String[] sm2PubkeyFile = mSafetyCardMT2.createSM2PubkeyFile(fId);
        if (SafetyCardMT2.RES_OK.equals(sm2PubkeyFile[0])) {
            Log.d(TAG, "公钥文件创建成功" + fId);
        } else {
            Log.d(TAG, "公钥文件创建失败" + fId + "====" + sm2PubkeyFile[0]);
        }
    }

    //创建私钥文件
    private void createPriKeyFile(String fId) {
        String[] sm2PrikeyFile = mSafetyCardMT2.createSM2PrikeyFile(fId);
        if (SafetyCardMT2.RES_OK.equals(sm2PrikeyFile[0])) {
            Log.d(TAG, "私钥文件创建成功" + fId);
        } else {
            Log.d(TAG, "私钥文件创建失败" + fId + "====" + sm2PrikeyFile[0]);
        }
    }

    //配对
    private void peidui() {
        //关联文件并创建公私密钥对 公钥文件ID 私钥文件ID  是否导出公钥
        String a[] = mSafetyCardMT2.generateSM2Key("0270", "0271", "01");
        if (SafetyCardMT2.RES_OK.equals(a[0])) {
            tagPubKey = a[1];
            Log.d(TAG, "秘钥配对成功,导出公钥值===" + a[1]);
        } else {
            Log.d(TAG, "秘钥配对失败" + a[0]);
        }
    }

    //使用公钥进行加密
    private String sm2Enc(String pubFId, String data) {
        //转化成16进制的字符串
        data = Util.getHexString(data.getBytes());
        String[] encResult = mSafetyCardMT2.SM2PublicKeyEnc(pubFId, data);
        if (SafetyCardMT2.RES_OK.equals(encResult[0])) {
            //SM2加密成功
            sm2MiWen = encResult[1];
            Log.d(TAG, "SM2加密成功" + encResult[1]);
            return sm2MiWen;
        } else {
            Log.d(TAG, "SM2加密失败" + encResult[0]);
        }
        return null;
    }

    //使用私钥进行解密
    private void sm2Dec(String priFId, String data,boolean changeHex) {
        String[] result = mSafetyCardMT2.SM2PrivateKeyDec(priFId, data);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            //SM2解密成功
            if(!changeHex){
                Log.d(TAG, "SM2解密数据===" + result[1]);
                return;
            }
            Log.d(TAG, "SM2解密成功" + result[1]);
            //16进制的字符串转换字节流
            byte[] bytes = Util.hexStringToBytes(result[1]);
            try {
                String str = new String(bytes, "UTF-8");
                Log.d(TAG, "SM2解密数据===" + str);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        } else {
            Log.d(TAG, "SM2解密失败" + result[0]);
        }
    }

    //从外部导入公钥文件
    private void importSM2PubKey(String fId, String tagPubKey) {
        String[] importResult = mSafetyCardMT2.importSM2PubKey(fId, tagPubKey);
        if (SafetyCardMT2.RES_OK.equals(importResult[0])) {
            Log.d(TAG, "SM2公钥导入成功===" + importResult[0]);
            //导出公钥
            String c[] = mSafetyCardMT2.exportSM2PublicKey("0272");
            Log.d(TAG, "SM2公钥导出成功===" + c[1]);
        } else {
            Log.d(TAG, "SM2公钥导入失败===" + importResult[0]);
        }
    }

    /**
     * 计算摘要
     * 00：首块  01：仅此一块  02：中间块   03：最后一块
     *
     * @param hashType 01：SHA1 02：SHA256   03：SM3
     * @param inData 待计算的数据 不能超过240字节
     */
    private void digest(String hashType, String inData) {
        byte[] bytes = Util.hexStringToBytes(inData);
        Log.i(TAG, "摘要的字节数====" + bytes.length);
        if (bytes.length <= 240) {
            String[] result = mSafetyCardMT2.digestCal("01", hashType, inData);
            if (SafetyCardMT2.RES_OK.equals(result[0])) {
                //获取摘要数据成功
                digestData = result[1];
                Log.d(TAG, "获取摘要数据成功===" + result[1]);
            } else {
                Log.d(TAG, "获取摘要数据失败===" + result[0]);
            }
            return;
        }
        if (bytes.length <= 480) {
            //分成首块和尾块发送
            String headData = inData.substring(0, inData.length() / 2);
            String endData = inData.substring(inData.length() / 2, inData.length());
            String[] headResult = mSafetyCardMT2.digestCal("00", hashType, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送尾块
                String[] endResult = mSafetyCardMT2.digestCal("03", hashType, endData);
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //获取摘要数据成功
                    digestData = endResult[1];
                    Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                } else {
                    Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return;
        }
        if (bytes.length <= 720) {
            //分成首块、中间块和尾块发送
            String headData = inData.substring(0, inData.length() / 3);
            String midData = inData.substring(inData.length() / 3,
                    inData.length() - inData.length() / 3 - 1);
            String endData =
                    inData.substring(inData.length() - inData.length() / 3 - 1, inData.length());

            String[] headResult = mSafetyCardMT2.digestCal("00", hashType, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送中间块
                String[] midResult = mSafetyCardMT2.digestCal("02", hashType, midData);
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    //中间块发送成功 继续发送尾块
                    String[] endResult = mSafetyCardMT2.digestCal("03", hashType, endData);
                    if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                        //获取摘要数据成功
                        digestData = endResult[1];
                        Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                    } else {
                        Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                    }
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return;
        }
        //分成首块、中间块和尾块发送
        String headData = inData.substring(0, 240);
        //发送首块数据
        String[] headResult = mSafetyCardMT2.digestCal("00", hashType, headData);
        if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
            //首块数据发送成功
            String midData = inData.substring(240, inData.length() - 240);
            while (midData.length() > 240) {
                //拆分中间块数据
                String[] midResult =
                        mSafetyCardMT2.digestCal("02", hashType, inData.substring(0, 240));
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    midData = midData.substring(240, midData.length());
                }
            }
            //发送最后一块中间数据
            String[] midResult =
                    mSafetyCardMT2.digestCal("02", hashType, inData.substring(0, midData.length()));
            if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                String endData = inData.substring(inData.length() - 240, inData.length());
                String[] endResult = mSafetyCardMT2.digestCal("03", hashType, endData);
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //获取摘要数据成功
                    digestData = endResult[1];
                    Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                } else {
                    Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
    }

    /**
     * 使用私钥进行加签
     *
     * @param fId 私钥文件的ID
     * @param digestData 摘要数据
     */
    private void priKeySign(String fId, String digestData) {
        String[] result = mSafetyCardMT2.SM2PrivateKeySign(fId, digestData);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            hashData = result[1];
            Log.d(TAG, "私钥加签成功===" + hashData);
        } else {
            Log.d(TAG, "私钥加签失败===" + result[0]);
        }
    }

    /**
     * 公钥验签
     *
     * @param fId 存放公钥的文件
     * @param digestData 摘要值
     * @param hashData 私钥加签的数据
     */
    private void pubKeyVerify(String fId, String digestData, String hashData) {
        String[] result = mSafetyCardMT2.SM2PublicKeyVerify(fId, digestData, hashData);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "公钥验签成功===" + result[1]);
        } else {
            Log.d(TAG, "公钥验签失败===" + result[0]);
        }
    }

    //创建对称秘钥的文件夹
    private void createSM4File(int fileNum) {
        if (fileNum < 1) {
            return;
        }
        String[] symmKeyFile = mSafetyCardMT2.createSymmKeyFile(fileNum);
        if (SafetyCardMT2.RES_OK.equals(symmKeyFile[0])) {
            Log.d(TAG, "对称秘钥文件夹创建成功===" + symmKeyFile[1]);
        } else {
            Log.d(TAG, "对称秘钥文件夹创建失败===" + symmKeyFile[0]);
        }
    }

    /**
     * 明文导入对称秘钥值
     *
     * @param keyType 0x00:GP,0x01:SM1, 0x02:SM4,0x04:DES,0x05:DES3,0x06:AES,0x07:SSF33
     * @param keyId 对称密钥文件ID
     * @param key 对称密钥
     */
    private void importSM4Key(byte keyType, byte keyId, String key) {
        String[] symmetryKey = mSafetyCardMT2.importSymmKey(keyType, keyId, key);
        if (SafetyCardMT2.RES_OK.equals(symmetryKey[0])) {
            Log.d(TAG, "对称秘钥导入成功===" + symmetryKey[1]);
        } else {
            Log.d(TAG, "对称秘钥导入失败===" + symmetryKey[0]);
        }
    }

    /**
     * 使用非对称/对称秘钥加密导入对称秘钥  非对称算法 非对称私钥  对称秘钥算法 对称秘钥文件 对称秘钥值
     *
     * @param keyType 加密类型：0x00：对称加密、 0x04：RSA1024加密导入 、0x05：SM2加密导入、0x06：RSA1280加密导入、0x07：RSA2048加密导入
     * @param impSymmKeyId 存放对称秘钥的文件ID
     * @param alg 对称秘钥的算法 02：SM4 。。。。
     * @param symmKeyId 对称秘钥文件的ID  如果选择0x00 这个值有效 priKeyFileID传入""
     * @param priKeyFileID 非对称秘钥的私钥文件ID,如果不选择0x00 这个值有效 symmKeyId""
     * @param keyCipher 要导入的秘钥值（这个值是秘文）
     */
    private void importSM4KeyWithSM2(byte keyType, int impSymmKeyId, String alg, String symmKeyId,
            String priKeyFileID, String keyCipher) {
        String[] result = mSafetyCardMT2.importSymmetricKey(keyType, impSymmKeyId, alg, symmKeyId,
                priKeyFileID, keyCipher);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "加密对称秘钥导入成功===" + result[1]);
        } else {
            Log.d(TAG, "加密对称秘钥导入失败===" + result[0]);
        }
    }

    /**
     * 明文导入会话秘钥
     *
     * @param sessionId 会话秘钥的ID 1-5  1：代表更新sessionId=0的会话秘钥  2：代表更新sessionId=1的会话秘钥 依次类推
     * @param sessionType 会话秘钥的类型 01：SM1  02：SM4  04:DES  05:DES-128
     * @param sessionKey 会话秘钥值(值要符合选择的sessionType类型的要求)
     * SM1和SM4的秘钥长度128位
     */
    private void importSessionKeyMingW(int sessionId, String sessionType, String sessionKey) {
        String[] result = mSafetyCardMT2.importSessionKey(sessionId, sessionType, sessionKey);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "明文会话秘钥导入成功===" + result[1]);
        } else {
            Log.d(TAG, "明文会话秘钥导入失败===" + result[0]);
        }
    }

    /**
     * 秘文导入会话秘钥
     *
     * @param sessionId 会话秘钥的ID
     * @param sessionType 会话秘钥的类型
     * @param importMode 明文导入0x00，密文导入0x01
     * @param encType 加密类型：SM2:0x01  RSA1024:0x00  RSA1280:0x02  RSA2048:0x03
     * @param sessionKeyIn 会话秘钥值
     * @param prikeyFileId 私钥文件的ID
     */
    private void importSessionKeyMiW(byte sessionId, byte sessionType, byte importMode,
            byte encType, String sessionKeyIn, String prikeyFileId) {
        String[] result =
                mSafetyCardMT2.MT2ImportSessionKey(sessionId, sessionType, importMode, encType,
                        sessionKeyIn, prikeyFileId);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "密文会话秘钥导入成功===" + result[1]);
        } else {
            Log.d(TAG, "密文会话秘钥导入失败===" + result[0]);
        }
    }

    /**
     * 明文导出会话秘钥
     *
     * @param sessionId 会话秘钥的ID
     * @param sessionType 会话秘钥的类型
     */
    private void exportSessionKeyWithMingW(int sessionId, String sessionType) {
        String[] result = mSafetyCardMT2.exportSessionKey(sessionId, sessionType);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "明文导出会话秘钥成功===" + result[1]);
        } else {
            Log.d(TAG, "明文导出会话秘钥失败===" + result[0]);
        }
    }

    /**
     * 秘文导出会话秘钥
     *
     * @param sessionKeyId 会话秘钥的ID
     * @param sessionType 会话秘钥的类型 SM1:0x01 SM4:0x02  DES:0x04  DES-128:0x05
     * @param exportMode 明文导出0x00，密文导出0x01
     * @param encType 对秘钥值加密的类型 RSA1024:0x00 RSA1280:0x02 RSA2048:0x03 SM2:0x01
     * @param pubkeyFileId 私钥文件的ID
     */
    private void exportSessionKeyWithMiW(byte sessionKeyId, byte sessionType, byte exportMode,
            byte encType, String pubkeyFileId) {
        String[] result =
                mSafetyCardMT2.MT2ExportSessionKey(sessionKeyId, sessionType, exportMode, encType,
                        pubkeyFileId);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "密文导出会话秘钥成功===" + result[1]);
            //进行SM2解密
            sm2Dec("0271", result[1].substring(4,result[1].length()),false);
        } else {
            Log.d(TAG, "密文导出会话秘钥失败===" + result[0]);
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
