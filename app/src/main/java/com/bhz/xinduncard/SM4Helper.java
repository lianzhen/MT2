package com.bhz.xinduncard;

/**
 * Created by 李安阵 on 2020/1/8
 * SM4加解密要求操作的数据必须是16字节的整数倍
 */

public class SM4Helper {

    //把要加密的数据转化成最终的字节数组
    public static byte[] fillDataTo16(byte[] input) {
        if (input == null) {
            return null;
        } else {
            int p = 16 - input.length % 16;
            byte[] res;
            if (p == 16) {
                res = new byte[input.length + 16];
            } else {
                res = new byte[input.length + p];
            }
            System.arraycopy(input, 0, res, 0, input.length);
            for (int i = 0; i < p; ++i) {
                res[input.length + i] = (byte) p;
            }
            return res;
        }
    }

    //解密数据是需要还原
    public static byte[] dataRestore(byte[] input) {
        if (input == null) {
            return null;
        } else {
            int length = input.length;
            byte finalByte = input[length - 1];
            byte[] res = new byte[length - finalByte];
            System.arraycopy(input, 0, res, 0, res.length);
            return res;
        }
    }
}
