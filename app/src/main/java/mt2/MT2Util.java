package mt2;

import android.util.Log;
import com.bhz.xinduncard.SM4Helper;
import com.bhz.xinduncard.Util;
import com.csizg.securitymt2.SafetyCardMT2;

/**
 * Created by 李安阵 on 2020/1/8
 */

public class MT2Util {
    private static String TAG = "MT2Util";
    private static SafetyCardMT2 mSafetyCardMT2;

    /**
     * 导出SM2公钥
     *
     * @param pubFId 存放SM2公钥的文件标识符
     * @return 公钥结构:ca40+公钥值+c120+公钥HASH值
     */
    public static String exportSM2PublicKey(String pubFId) {
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
    public static byte[] sm2Enc(String pubFId, byte[] data) {
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
    private static byte[] sm2Dec(String priFId, byte[] data) {
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

    //============================================================================

    /**
     * 计算摘要
     * 00：首块  01：仅此一块  02：中间块   03：最后一块
     *
     * @param hashType 01：SHA1 02：SHA256   03：SM3
     * @param bytes 待计算的数据 不能超过240字节
     */
    public static byte[] digest(String hashType, byte[] bytes) {
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
    public static byte[] priKeySign(String fId, byte[] digestData) {
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
    public static byte[] pubKeyVerify(String fId, byte[] digestData, byte[] hashData) {
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

    /**
     * 获取随机数
     *
     * @param length 长度  十六进制  例如：出入10，转换成十进制就是16，那么就会生成一个16字节的随机数，转换成16进制就是32位
     * @return 返回单位：字节
     */
    public static String getRandomNumber(String length) {
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
    public static void importSessionKeyMingW(int sessionId, String sessionType, String sessionKey) {
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
    public static String exportSessionKeyWithMingW(int sessionId, String sessionType) {
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

        byte[] resultByte = SM4Helper.fillDataTo16(bytes);
        String inData = Util.getHexString(resultByte);
        Log.i(TAG, "加密的字节数====" + resultByte.length);

        int quotient = bytes.length / 240;
        int remainder = bytes.length % 240;
        if (quotient == 0 || (quotient == 1 && remainder == 0)) {
            String[] result = mSafetyCardMT2.sessionKeyEncECB("00", sessionId, inData);
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
            String headData = inData.substring(0, 480);
            String endData = inData.substring(480, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送尾块
                String[] endResult = mSafetyCardMT2.sessionKeyEncECB("03", sessionId, endData);
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //对称加密数据成功
                    Log.d(TAG, "获取对称加密数据成功===" + endResult[1]);
                    return Util.hexStringToBytes(endResult[1]);
                } else {
                    Log.d(TAG, "获取对称加密数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        if (quotient == 2 || (quotient == 3 && remainder == 0)) {
            String headData = inData.substring(0, 480);
            String midData = inData.substring(480, 960);
            String endData = inData.substring(960, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送中间块
                String[] midResult = mSafetyCardMT2.sessionKeyEncECB("02", sessionId, midData);
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    //中间块发送成功 继续发送尾块
                    String[] endResult = mSafetyCardMT2.sessionKeyEncECB("03", sessionId, endData);
                    if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                        //获取秘文数据成功
                        Log.d(TAG, "获取对称加密数据成功===" + endResult[1]);
                        return Util.hexStringToBytes(endResult[1]);
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
        headData = inData.substring(0, 480);
        if (remainder == 0) {
            midData = inData.substring(480, inData.length() - 480);
            endData = inData.substring(inData.length() - 480, inData.length());
        } else {
            midData = inData.substring(480, inData.length() - remainder * 2);
            endData = inData.substring(inData.length() - remainder * 2, inData.length());
        }
        //发送首块数据
        String[] headResult = mSafetyCardMT2.sessionKeyEncECB("01", sessionId, headData);
        if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
            //首块数据发送成功
            while (midData.length() >= 480) {
                //拆分中间块数据
                String[] midResult =
                        mSafetyCardMT2.sessionKeyEncECB("02", sessionId, inData.substring(0, 480));
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    midData = midData.substring(480, midData.length());
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            }
            //发送尾块数据
            String[] endResult = mSafetyCardMT2.sessionKeyEncECB("03", sessionId, endData);
            if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                //获取秘文数据成功
                Log.d(TAG, "获取SM4加密数据成功===" + endResult[1]);
                return Util.hexStringToBytes(endResult[1]);
            } else {
                Log.d(TAG, "获取SM4加密数据失败===" + endResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
        return null;
    }

    //

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
        int quotient = bytes.length / 240;
        int remainder = bytes.length % 240;
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
            String headData = inData.substring(0, 480);
            String endData = inData.substring(480, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送尾块
                String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
                if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                    //对称解密数据成功
                    Log.d(TAG, "获取对称解密数据成功===" + endResult[1]);
                    return SM4Helper.dataRestore(Util.hexStringToBytes(endResult[1]));
                } else {
                    Log.d(TAG, "获取对称解密数据失败===" + endResult[0]);
                }
            } else {
                Log.d(TAG, "首块数据发送失败===" + headResult[0]);
            }
            return null;
        }
        if (quotient == 2 || (quotient == 3 && remainder == 0)) {
            String headData = inData.substring(0, 480);
            String midData = inData.substring(480, 960);
            String endData = inData.substring(960, inData.length());
            String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
            if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
                //首块发送成功 继续发送中间块
                String[] midResult = mSafetyCardMT2.sessionKeyDecECB("02", sessionId, midData);
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    //中间块发送成功 继续发送尾块
                    String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
                    if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                        //获取秘文数据成功
                        Log.d(TAG, "获取对称解密数据成功===" + endResult[1]);
                        return SM4Helper.dataRestore(Util.hexStringToBytes(endResult[1]));
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
        headData = inData.substring(0, 480);
        if (remainder == 0) {
            midData = inData.substring(480, inData.length() - 480);
            endData = inData.substring(inData.length() - 480, inData.length());
        } else {
            midData = inData.substring(480, inData.length() - remainder * 2);
            endData = inData.substring(inData.length() - remainder * 2, inData.length());
        }
        //发送首块数据
        String[] headResult = mSafetyCardMT2.sessionKeyDecECB("01", sessionId, headData);
        if (SafetyCardMT2.RES_OK.equals(headResult[0])) {
            //首块数据发送成功
            while (midData.length() >= 480) {
                //拆分中间块数据
                String[] midResult =
                        mSafetyCardMT2.sessionKeyDecECB("02", sessionId, inData.substring(0, 480));
                if (SafetyCardMT2.RES_OK.equals(midResult[0])) {
                    midData = midData.substring(480, midData.length());
                } else {
                    Log.d(TAG, "中间块数据发送失败===" + midResult[0]);
                }
            }
            //发送尾块数据
            String[] endResult = mSafetyCardMT2.sessionKeyDecECB("03", sessionId, endData);
            if (SafetyCardMT2.RES_OK.equals(endResult[0])) {
                //获取秘文数据成功
                Log.d(TAG, "获取SM4解密数据成功===" + endResult[1]);
                return SM4Helper.dataRestore(Util.hexStringToBytes(endResult[1]));
            } else {
                Log.d(TAG, "获取SM4解密数据失败===" + endResult[0]);
            }
        } else {
            Log.d(TAG, "首块数据发送失败===" + headResult[0]);
        }
        return null;
    }
}
