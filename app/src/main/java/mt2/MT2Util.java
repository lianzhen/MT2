package mt2;

import android.util.Log;
import com.bhz.xinduncard.FileManager;
import com.bhz.xinduncard.SM4;
import com.bhz.xinduncard.SM4Helper;
import com.bhz.xinduncard.SM4_Context;
import com.bhz.xinduncard.Util;
import com.csizg.securitymt2.SafetyCardMT2;
import java.io.UnsupportedEncodingException;

/**
 * Created by 李安阵 on 2020/1/8
 */

public class MT2Util {
    private static String TAG = "MT2Util";
    //===================================卡信息相关=================================================

    /**
     * 获取卡信息
     *
     * @param p2 01:获取SN号,02:Cos Version ,03:取当前目录剩余空间,04:取SPP_MAC+BLE_MAC,05:取卡中支持的APP的SHA-1值
     * @param le 和p2一一对应，01--08   02--02  03--04  04--0C   05-64
     */
    public static String getCardInfo(SafetyCardMT2 mSafetyCardMT2, String p2, String le) {
        String[] cardInfo = mSafetyCardMT2.getCardInfo(p2, le);
        if (SafetyCardMT2.RES_OK.equals(cardInfo[0])) {
            Log.d(TAG, "读取卡信息结果：" + cardInfo[1]);
            return cardInfo[1];
        }
        return null;
    }

    //返回单位是字节
    public static int getCardSize(SafetyCardMT2 mSafetyCardMT2) {
        String[] cardInfo = mSafetyCardMT2.getCardInfo("03", "04");
        if (SafetyCardMT2.RES_OK.equals(cardInfo[0])) {
            Log.d(TAG, "当前目录剩余可用空间：" + cardInfo[1]);
            return Util.decodeHEX(cardInfo[1]);
        }
        return 0;
    }

    //获取卡SN号
    public static String getCardSN(SafetyCardMT2 mSafetyCardMT2) {
        String[] cardInfo = mSafetyCardMT2.getCardInfo("01", "08");
        if (SafetyCardMT2.RES_OK.equals(cardInfo[0])) {
            Log.d(TAG, "SN号：" + cardInfo[1]);
            return cardInfo[1];
        }
        return null;
    }
    //===================================PIN码相关=================================================

    /**
     * 修改PIN码 默认的123456 这个api没有返回值
     *
     * @param oldPin 原PIN码
     * @param newPin 新PIN码
     */
    public static void changePIN(SafetyCardMT2 mSafetyCardMT2, String oldPin, String newPin) {
        oldPin = Util.getHexString(oldPin.getBytes());
        newPin = Util.getHexString(newPin.getBytes());
        String[] result = mSafetyCardMT2.changePIN(oldPin, newPin);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "PIN修改成功" + result[1]);
        } else {
            Log.d(TAG, "PIN修改失败" + result[0]);
        }
    }

    //PIN码认证
    public static void pinVerify(SafetyCardMT2 mSafetyCardMT2, String pin) {
        if (pin == null || "".equals(pin) || pin.length() != 6) {
            return;
        }
        pin = Util.getHexString(pin.getBytes());
        String[] pinResult = mSafetyCardMT2.verifyPIN(pin);
        if (SafetyCardMT2.RES_OK.equals(pinResult[0])) {
            Log.d(TAG, "PIN认证成功" + pinResult[1]);
        } else {
            Log.d(TAG, "PIN认证失败" + pinResult[0]);
        }
    }
    //===================================SM2相关=================================================

    /**
     * 导出SM2公钥
     *
     * @param pubFId 存放SM2公钥的文件标识符
     * @return 公钥结构:ca40+公钥值+c120+公钥HASH值
     */
    public static String exportSM2PublicKey(SafetyCardMT2 mSafetyCardMT2, String pubFId) {
        String result[] = mSafetyCardMT2.exportSM2PublicKey(pubFId);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            //SM2公钥导出成功
            Log.d(TAG, "SM2公钥导出成功" + result[1]);
            return result[1];
        } else {
            Log.d(TAG, "SM2加密失败" + result[0]);
        }
        return null;
    }

    /**
     * 使用公钥进行加密
     *
     * @param pubFId 存放SM2公钥的文件标识符
     * @param data 需要加密的数据
     */
    public static byte[] sm2Enc(SafetyCardMT2 mSafetyCardMT2, String pubFId, byte[] data) {
        //byte数组转换成16进制
        String hexStr = Util.getHexString(data);
        String[] encResult = mSafetyCardMT2.SM2PublicKeyEnc(pubFId, hexStr);
        if (SafetyCardMT2.RES_OK.equals(encResult[0])) {
            //SM2加密成功
            Log.d(TAG, "SM2加密成功" + encResult[1]);
            return Util.hexStringToBytes(encResult[1]);
        } else {
            Log.d(TAG, "SM2加密失败" + encResult[0]);
        }
        return null;
    }

    /**
     * 使用私钥进行解密
     *
     * @param priFId 存放私钥的文件标识符
     * @param data 需要解密的数据
     */
    private static byte[] sm2Dec(SafetyCardMT2 mSafetyCardMT2, String priFId, byte[] data) {
        String hexString = Util.getHexString(data);
        String[] result = mSafetyCardMT2.SM2PrivateKeyDec(priFId, hexString);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            //SM2解密成功
            Log.d(TAG, "SM2解密成功" + result[1]);
            //16进制的字符串转换字节流
            return Util.hexStringToBytes(result[1]);
        } else {
            Log.d(TAG, "SM2解密失败" + result[0]);
        }
        return null;
    }

    //===================================SM3相关 计算摘要 加签 验签=================================================

    /**
     * 计算摘要
     * 00：首块  01：仅此一块  02：中间块   03：最后一块
     *
     * @param hashType 01：SHA1 02：SHA256   03：SM3
     * @param bytes 待计算的数据 不能超过240字节
     */
    public static byte[] digest(SafetyCardMT2 mSafetyCardMT2, String hashType, byte[] bytes) {
        Log.i(TAG, "摘要的字节数====" + bytes.length);
        String inData = Util.getHexString(bytes);
        if (bytes.length <= 240) {
            String[] result = mSafetyCardMT2.digestCal("01", hashType, inData);
            if (SafetyCardMT2.RES_OK.equals(result[0])) {
                //获取摘要数据成功
                Log.d(TAG, "获取摘要数据成功===" + result[1]);
                return Util.hexStringToBytes(result[1]);
            } else {
                Log.d(TAG, "获取摘要数据失败===" + result[0]);
            }
            return null;
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
                    Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                    return Util.hexStringToBytes(endResult[1]);
                } else {
                    Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
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
                        Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                        return Util.hexStringToBytes(endResult[1]);
                    } else {
                        Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                    }
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
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
                        mSafetyCardMT2.digestCal("02", hashType, midData.substring(0, 240));
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
                    Log.d(TAG, "获取摘要数据成功===" + endResult[1]);
                    return Util.hexStringToBytes(endResult[1]);
                } else {
                    Log.d(TAG, "获取摘要数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
        return null;
    }

    /**
     * 使用私钥进行加签
     *
     * @param fId 私钥文件的ID
     * @param digestData 摘要数据
     */
    public static byte[] priKeySign(SafetyCardMT2 mSafetyCardMT2, String fId, byte[] digestData) {
        String hexString = Util.getHexString(digestData);
        String[] result = mSafetyCardMT2.SM2PrivateKeySign(fId, hexString);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "私钥加签成功===" + result[1]);
            return Util.hexStringToBytes(result[1]);
        } else {
            Log.d(TAG, "私钥加签失败===" + result[0]);
        }
        return null;
    }

    /**
     * 公钥验签
     *
     * @param fId 存放公钥的文件
     * @param digestData 摘要值
     * @param hashData 私钥加签的数据
     */
    public static byte[] pubKeyVerify(SafetyCardMT2 mSafetyCardMT2, String fId, byte[] digestData,
            byte[] hashData) {
        String hexDigest = Util.getHexString(digestData);
        String hexData = Util.getHexString(hashData);
        String[] result = mSafetyCardMT2.SM2PublicKeyVerify(fId, hexDigest, hexData);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "公钥验签成功===" + result[1]);
            return Util.hexStringToBytes(result[1]);
        } else {
            Log.d(TAG, "公钥验签失败===" + result[0]);
        }
        return null;
    }
    //==============================================SM4相关=================================================

    /**
     * 获取随机数
     *
     * @param length 长度  十六进制  例如：出入10，转换成十进制就是16，那么就会生成一个16字节的随机数，转换成16进制就是32位
     * @return 返回单位：字节
     */
    public static String getRandomNumber(SafetyCardMT2 mSafetyCardMT2, String length) {
        String[] challenge = mSafetyCardMT2.getChallenge(length);
        if (SafetyCardMT2.RES_OK.equals(challenge[0])) {
            Log.d(TAG, "随机数生成成功===" + challenge[1]);
            return challenge[1];
        } else {
            Log.d(TAG, "随机数生成失败===" + challenge[0]);
        }
        return null;
    }

    /**
     * 明文导入会话秘钥
     *
     * @param sessionId 会话秘钥的ID 1-5  1：代表更新sessionId=0的会话秘钥  2：代表更新sessionId=1的会话秘钥 依次类推
     * @param sessionType 会话秘钥的类型 01：SM1  02：SM4  04:DES  05:DES-128
     * @param sessionKey 会话秘钥值(值要符合选择的sessionType类型的要求)
     * SM1和SM4的秘钥长度128位
     */
    public static void importSessionKeyMingW(SafetyCardMT2 mSafetyCardMT2, int sessionId,
            String sessionType, String sessionKey) {
        String[] result = mSafetyCardMT2.importSessionKey(sessionId, sessionType, sessionKey);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "明文会话秘钥导入成功===" + result[1]);
        } else {
            Log.d(TAG, "明文会话秘钥导入失败===" + result[0]);
        }
    }

    /**
     * 明文导出会话秘钥
     *
     * @param sessionId 会话秘钥的ID 同上
     * @param sessionType 会话秘钥的类型 同上
     * @return 返回值：c1xx+秘钥长度
     */
    public static String exportSessionKeyWithMingW(SafetyCardMT2 mSafetyCardMT2, int sessionId,
            String sessionType) {
        String[] result = mSafetyCardMT2.exportSessionKey(sessionId, sessionType);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "明文导出会话秘钥成功===" + result[1]);
            return result[1];
        } else {
            Log.d(TAG, "明文导出会话秘钥失败===" + result[0]);
        }
        return null;
    }

    /**
     * 对称秘钥 ECB模式加密
     *
     * @param sessionId 存放会话秘钥的文件Id
     * @param bytes 待加密的数据
     */
    public static byte[] sessionEncEcb(SafetyCardMT2 mSafetyCardMT2, String sessionId,
            byte[] bytes) {
        String inData = Util.getHexString(bytes);
        Log.i(TAG, "加密的字节数====" + bytes.length);
        StringBuffer builder = new StringBuffer();

        int quotient = bytes.length / 224;
        int remainder = bytes.length % 224;
        if (quotient == 0 || (quotient == 1 && remainder == 0)) {
            byte[] b = SM4Helper.fillDataTo16(bytes);
            String[] result =
                    mSafetyCardMT2.sessionKeyEncECB("00", sessionId, Util.getHexString(b));
            if (SafetyCardMT2.RES_OK.equals(result[0])) {
                //对称加密数据成功
                Log.d(TAG, "获取对称加密数据成功===" + result[1]);
                return Util.hexStringToBytes(result[1]);
            } else {
                Log.d(TAG, "获取对称加密数据失败===" + result[0]);
            }
            return null;
        }
        if (quotient == 1 || (quotient == 2 && remainder == 0)) {
            //分成首块和尾块发送
            String headData = inData.substring(0, 448);
            String endData = inData.substring(448, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送尾块
                builder.append(headResult[1]);//拼接首块数据
                byte[] b = SM4Helper.fillDataTo16(Util.hexStringToBytes(endData));
                String[] endResult =
                        mSafetyCardMT2.sessionKeyEncECB("03", sessionId, Util.getHexString(b));
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //对称加密数据成功
                    builder.append(endResult[1]);//拼接尾块数据
                    Log.d(TAG, "获取对称加密数据成功===" + endResult[1]);
                    return Util.hexStringToBytes(builder.toString());
                } else {
                    Log.d(TAG, "获取对称加密数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        if (quotient == 2 || (quotient == 3 && remainder == 0)) {
            String headData = inData.substring(0, 448);
            String midData = inData.substring(448, 896);
            String endData = inData.substring(896, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送中间块
                builder.append(headResult[1]);//拼接首块数据
                String[] midResult = mSafetyCardMT2.sessionKeyEncECB("02", sessionId, midData);
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    //中间块发送成功 继续发送尾块
                    builder.append(midResult[1]);//拼接中间块数据
                    byte[] b = SM4Helper.fillDataTo16(Util.hexStringToBytes(endData));
                    String[] endResult =
                            mSafetyCardMT2.sessionKeyEncECB("03", sessionId, Util.getHexString(b));
                    if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                        //获取秘文数据成功
                        Log.d(TAG, "获取对称加密数据成功===" + endResult[1]);
                        builder.append(endResult[1]);//拼接尾块数据
                        return Util.hexStringToBytes(builder.toString());
                    } else {
                        Log.d(TAG, "获取对称加密数据失败===" + endResult[0]);
                    }
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        //分成首块、多个中间块和尾块发送
        String headData, midData, endData;
        headData = inData.substring(0, 448);
        if (remainder == 0) {
            midData = inData.substring(448, inData.length() - 448);
            endData = inData.substring(inData.length() - 448, inData.length());
        } else {
            midData = inData.substring(448, inData.length() - remainder * 2);
            endData = inData.substring(inData.length() - remainder * 2, inData.length());
        }
        //发送首块数据
        String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
        if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
            //首块数据发送成功
            builder.append(headResult[1]);
            while (midData.length() >= 448) {
                //拆分中间块数据
                Log.d(TAG, "中间块数据是===" + midData);
                String[] midResult =
                        mSafetyCardMT2.sessionKeyEncECB("02", sessionId, midData.substring(0, 448));
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    midData = midData.substring(448, midData.length());
                    Log.d(TAG, "中间块数据发送成功===" + midResult[1]);
                    builder.append(midResult[1]);
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            }
            //发送尾块数据
            byte[] b = SM4Helper.fillDataTo16(Util.hexStringToBytes(endData));
            String[] endResult =
                    mSafetyCardMT2.sessionKeyEncECB("03", sessionId, Util.getHexString(b));
            if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                //获取秘文数据成功
                Log.d(TAG, "获取SM4加密数据成功===" + endResult[1]);
                builder.append(endResult[1]);
                return Util.hexStringToBytes(builder.toString());
            } else {
                Log.d(TAG, "获取SM4加密数据失败===" + endResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
        return null;
    }

    /**
     * 对称秘钥 ECB模式解密
     *
     * @param sessionId 存放会话秘钥的文件Id
     * @param bytes 待解密的数据
     */
    public static byte[] sessionDecEcb(SafetyCardMT2 mSafetyCardMT2, String sessionId,
            byte[] bytes) {
        String inData = Util.getHexString(bytes);
        Log.i(TAG, "解密的字节数====" + bytes.length);
        int quotient = bytes.length / 224;
        int remainder = bytes.length % 224;
        StringBuffer builder = new StringBuffer();
        if (quotient == 0 || (quotient == 1 && remainder == 0)) {
            String[] result = mSafetyCardMT2.sessionKeyDecECB("00", sessionId, inData);
            if (SafetyCardMT2.RES_OK.equals(result[0])) {
                //对称解密数据成功
                Log.d(TAG, "获取对称解密数据成功===" + result[1]);
                return SM4Helper.dataRestore(Util.hexStringToBytes(result[1]));
            } else {
                Log.d(TAG, "获取对称解密数据失败===" + result[0]);
            }
            return null;
        }
        if (quotient == 1 || (quotient == 2 && remainder == 0)) {
            //分成首块和尾块发送
            String headData = inData.substring(0, 448);
            String endData = inData.substring(448, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送尾块
                builder.append(headResult[1]);
                String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //对称解密数据成功
                    builder.append(endResult[1]);
                    Log.d(TAG, "获取对称解密数据成功===" + endResult[1]);
                    return SM4Helper.dataRestore(Util.hexStringToBytes(builder.toString()));
                } else {
                    Log.d(TAG, "获取对称解密数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        if (quotient == 2 || (quotient == 3 && remainder == 0)) {
            String headData = inData.substring(0, 448);
            String midData = inData.substring(448, 896);
            String endData = inData.substring(896, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送中间块
                builder.append(headResult[1]);
                String[] midResult = mSafetyCardMT2.sessionKeyDecECB("02", sessionId, midData);
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    //中间块发送成功 继续发送尾块
                    builder.append(midResult[1]);
                    String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
                    if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                        //获取秘文数据成功
                        builder.append(endResult[1]);
                        Log.d(TAG, "获取对称解密数据成功===" + endResult[1]);
                        return SM4Helper.dataRestore(Util.hexStringToBytes(builder.toString()));
                    } else {
                        Log.d(TAG, "获取对称解密数据失败===" + endResult[0]);
                    }
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        //分成首块、多个中间块和尾块发送
        String headData, midData, endData;
        headData = inData.substring(0, 448);
        if (remainder == 0) {
            midData = inData.substring(448, inData.length() - 448);
            endData = inData.substring(inData.length() - 448, inData.length());
        } else {
            midData = inData.substring(448, inData.length() - remainder * 2);
            endData = inData.substring(inData.length() - remainder * 2, inData.length());
        }
        //发送首块数据
        String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
        if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
            //首块数据发送成功
            builder.append(headResult[1]);
            while (midData.length() >= 448) {
                //拆分中间块数据
                String[] midResult =
                        mSafetyCardMT2.sessionKeyDecECB("02", sessionId, midData.substring(0, 448));
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    builder.append(midResult[1]);
                    Log.d(TAG, "中间块数据发送成功===" + midResult[1]);
                    midData = midData.substring(448, midData.length());
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            }
            //发送尾块数据
            String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
            if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                //获取秘文数据成功
                Log.d(TAG, "获取SM4解密数据成功===" + endResult[1]);
                builder.append(endResult[1]);
                return SM4Helper.dataRestore(Util.hexStringToBytes(builder.toString()));
            } else {
                Log.d(TAG, "获取SM4解密数据失败===" + endResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
        return null;
    }
    //===================================二进制文件数据存储和读取相关=================================================

    /**
     * 读二进制文件
     *
     * @param sfi 创建二进制文件的短文件标识符
     */
    public static String readBinary(SafetyCardMT2 mSafetyCardMT2, int sfi) {
        String[] result = mSafetyCardMT2.readBinary(sfi, "00", "", false);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            // 把十六进制的数据转化成java String
            byte b[] = Util.hexStringToBytes(result[1]);
            String data = "";
            try {
                data = new String(b, "utf-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            int index = data.lastIndexOf("}");
            data = data.substring(0, index + 1);
            Log.d(TAG, "读二进制文件===" + data);
            return data;
        } else {
            Log.d(TAG, "读进制文件" + result[0]);
        }
        return null;
    }

    /**
     * 写二进制文件
     *
     * @param sfi 创建二进制文件的短文件标识符
     * @param data 要写入的数据
     */
    public static void writeBinary(SafetyCardMT2 mSafetyCardMT2, int sfi, String data) {
        String[] result = mSafetyCardMT2.updateBinary(sfi, "00", data, false);
        if (SafetyCardMT2.RES_OK.equals(result[0])) {
            Log.d(TAG, "写二进制文件成功: " + data.getBytes().length);
        } else {
            Log.d(TAG, "写二进制文件" + result[0]);
        }
    }

    /**
     * 进行外部认证
     *
     * @param fileName 文件名
     */
    public static boolean externalAuth(SafetyCardMT2 mSafetyCardMT2, String fileName) {
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
            return true;
        } else {
            Log.d(TAG, "外部认证失败" + result15[0]);
        }
        return false;
    }

    //创建MF
    public static boolean createMF(SafetyCardMT2 mSafetyCardMT2) {
        String[] mf = mSafetyCardMT2.createMF();
        if (SafetyCardMT2.RES_OK.equals(mf[0])) {
            Log.d(TAG, "创建MF" + mf[1]);
            return true;
        } else {
            Log.d(TAG, "创建MF" + mf[0]);
        }
        return false;
    }
    //删除MF
    public static boolean deleteMF(SafetyCardMT2 mSafetyCardMT2) {
        String[] delMF = mSafetyCardMT2.delMF();
        if (SafetyCardMT2.RES_OK.equals(delMF[0])) {
            Log.d(TAG, "删除MF" + delMF[1]);
            return true;
        } else {
            Log.d(TAG, "删除MF" + delMF[0]);
        }
        return false;
    }
    //创建MF的key文件
    public static void createMFKey(SafetyCardMT2 mSafetyCardMT2) {
        String[] key = mSafetyCardMT2.createKey();
        if (SafetyCardMT2.RES_OK.equals(key[0])) {
            Log.d(TAG, "创建MF_Key文件" + key[1]);
            //装载Key值
            //1.装载主控秘钥控制MF下文件的建立和密钥的写入
            writeKey(mSafetyCardMT2,"00", "01", "F0110401FF436F7265536869656C6453414D434F53", true);
            //系统维护秘钥
            writeKey(mSafetyCardMT2,"01", "01", "F02104FFFF44414D4B44414D4B44414D4B44414D4B", true);
            //外部认证的key
            writeKey(mSafetyCardMT2,"02", "01", "F0110401FF414446312D45544B414446312D45544B", true);
            //PIN认证的key
            writeKey(mSafetyCardMT2,"0A", "01", "F021FF02FF313233343536FFFFFFFFFFFFFFFFFFFF", true);
        } else {
            Log.d(TAG, "创建Key" + key[0]);
        }
    }
    //创建ADF的key文件
    public static void createADFKey(SafetyCardMT2 mSafetyCardMT2) {
        String[] key = mSafetyCardMT2.createFile("0000", "1F10FFFFFFFFFFFF");
        if (SafetyCardMT2.RES_OK.equals(key[0])) {
            Log.d(TAG, "创建ADF_Key文件" + key[1]);
            //装载Key值
            //主控秘钥-控制DF下文件的建立和秘钥的写入
            writeKey(mSafetyCardMT2,"00", "01", "F0110401FF436F7265536869656C644D5478303031", true);
            //维护秘钥key
            writeKey(mSafetyCardMT2,"01", "01", "F02104FFFF4144463144414D4B4144463144414D4B", true);
            //外部认证秘钥key
            writeKey(mSafetyCardMT2,"02", "01", "F01104FFFF414446312D45544B414446312D45544B", true);
            //PIN认证key
            writeKey(mSafetyCardMT2,"0A", "01", "F021FF02FF313233343536FFFFFFFFFFFFFFFFFFFF", true);
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
    private static void writeKey(SafetyCardMT2 mSafetyCardMT2,String keyType, String keyId, String data, boolean isPlain) {
        mSafetyCardMT2.writeKey(keyType, keyId, data, isPlain);
    }
    //创建ADF文件
    public static void createADF(SafetyCardMT2 mSafetyCardMT2) {
        //200K大小
        String[] adf1 =
                mSafetyCardMT2.createFile("ADF1", "18032000F1F1FFFFFFFFFFFFFFFF43534D5478303031");
        if (SafetyCardMT2.RES_OK.equals(adf1[0])) {
            Log.d(TAG, "ADF1创建成功>>>>>>>>>>>>>>>>>>>>>>>>>>");
            //装载key值
            createADFKey(mSafetyCardMT2);
        } else {
            Log.d(TAG, "ADF1创建" + adf1[0]);
        }
    }
    /**
     * 选择文件目录
     *
     * @param fileId 文件标识符
     */
    private void selectFileByFId(SafetyCardMT2 mSafetyCardMT2, String fileId) {
        String[] result14 = mSafetyCardMT2.selectFile("00", fileId);
        if (result14[0] != null && SafetyCardMT2.RES_OK.equalsIgnoreCase(result14[0])) {
            //进行MF文件外部认证
            if ("3F00".equals(fileId)) {
                Log.d(TAG, "选择主控目录成功" + result14[1]);
                externalAuth(mSafetyCardMT2, fileId);
            } else if ("ADF1".equals(fileId)) {
                //ADF1文件的外部认证
                Log.d(TAG, "选择ADF1目录成功" + result14[1]);
                externalAuth(mSafetyCardMT2, fileId);
            }
        } else {
            Log.d(TAG, "选择指定目录失败" + result14[1]);
        }
    }
}
