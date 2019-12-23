package com.bhz.xinduncard;

import android.graphics.Bitmap;
import android.graphics.Camera;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

/**
 * Created by hu on 2018/1/25.
 */

public class FileManager {

    private static final char[] bcdLookup = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final char[] base64EncodeChars = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
    private static byte[] base64DecodeChars = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

    public FileManager() {
    }

    public static void saveConfig(String dir, String fileName, Properties properties) {
        try {
            String localFile = dir + "/" + fileName;
            FileOutputStream s = new FileOutputStream(localFile, false);
            properties.store(s, "");
        } catch (Exception var5) {
            ;
        }

    }

    public static Properties loadConfig(String file) {
        Properties properties = new Properties();
        File afile = new File(file);

        try {
            if(!afile.exists()) {
                return null;
            }

            FileInputStream s = new FileInputStream(file);
            properties.load(s);
        } catch (Exception var4) {
            ;
        }

        return properties;
    }

    public static boolean delFoldAndFile(String foldPath) {
        File file = new File(foldPath);
        boolean localState = false;

        try {
            if(file.exists()) {
                if(file.isFile()) {
                    file.delete();
                } else if(file.isDirectory()) {
                    File[] files = file.listFiles();

                    for(int i = 0; i < files.length; ++i) {
                        delFile(files[i]);
                    }
                }

                localState = file.delete();
            } else {
                System.out.println("所删除的文件不存在！\n");
            }
        } catch (Exception var5) {
            ;
        }

        return localState;
    }

    private static void delFile(File file) {
        try {
            if(file.isFile()) {
                file.delete();
            }
        } catch (Exception var2) {
            ;
        }

    }

    public static String IntToByteHex(int mInt) {
        String localString = null;
        int localInt = mInt;
        byte[] localbyte = new byte[4];

        for(int k = 0; k < 4; ++k) {
            localbyte[3 - k] = (byte)(localInt >> k * 8 & 255);
        }

        localString = bytesToHex(localbyte);
        return localString;
    }

    public static String IntToByteOneHex(int mInt) {
        String localString = null;
        byte[] localbyte = new byte[]{(byte)mInt};
        localString = bytesToHex(localbyte);
        return localString;
    }

    public static int ByteToIntHex(byte[] mbyte) {
        int localInt = 0;
        byte[] localbyte = new byte[4];
        System.arraycopy(mbyte, 0, localbyte, 0, mbyte.length);

        for(int k = 0; k < 4; ++k) {
            localInt &= -256;
            int temp = localbyte[k] & 255;
            localInt |= temp;
            System.out.printf("\nlocalInt = 0x%x", new Object[]{Integer.valueOf(localInt)});
            if(k < 3) {
                localInt <<= 8;
            }
        }

        return localInt;
    }

    public static final String bytesToHex(byte[] bcd) {
        if(bcd == null) {
            return "";
        } else {
            StringBuffer s = new StringBuffer(bcd.length * 2);

            for(int i = 0; i < bcd.length; ++i) {
                s.append(bcdLookup[bcd[i] >>> 4 & 15]);
                s.append(bcdLookup[bcd[i] & 15]);
            }

            return s.toString();
        }
    }

    public static final byte[] hexToBytes(String s) {
        byte[] bytes = new byte[s.length() / 2];

        for(int i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte)Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }

    public static String characterTousc2(String zw, boolean f80) {
        byte[] b = null;

        try {
            b = zw.getBytes("UnicodeBigUnmarked");
        } catch (UnsupportedEncodingException var7) {
            var7.printStackTrace();
        }

        String strTmp = "";
        StringBuffer strBuffer = new StringBuffer(b.length * 2);

        for(int i = 0; i < b.length; ++i) {
            int nTmp = b[i] & 255;

            for(strTmp = Integer.toHexString(nTmp); strTmp.length() < 2; strTmp = "0" + strTmp) {
                ;
            }

            strTmp = strTmp.toUpperCase();
            strBuffer.append(strTmp);
        }

        String returnstr = strBuffer.toString();
        if(f80) {
            returnstr = "80" + returnstr;
            return returnstr;
        } else {
            return returnstr;
        }
    }

    public static String gb2312ToShow(byte[] gb2312) {
        String sTemp = null;

        try {
            sTemp = new String(gb2312, "GB2312");
        } catch (UnsupportedEncodingException var3) {
            var3.printStackTrace();
        }

        return sTemp;
    }

    public static String ucs2ToCharacter(String ucs) {
        byte[] bUnicode = hexToBytes(ucs);
        String sTemp = null;

        try {
            sTemp = new String(bUnicode, "UTF-16BE");
        } catch (UnsupportedEncodingException var4) {
            var4.printStackTrace();
        }

        return sTemp;
    }

    public static byte[] getPhotoData(String filePath) {
        File file = new File(filePath);
        InputStream inStream = null;
        ByteArrayOutputStream outStream = null;
        byte[] localdata = null;

        try {
            if(file.exists()) {
                byte[] buffer = new byte[1024];
                inStream = new FileInputStream(file);
                outStream = new ByteArrayOutputStream();

                int len;
                while((len = inStream.read(buffer)) != -1) {
                    outStream.write(buffer, 0, len);
                }

                localdata = outStream.toByteArray();
                return localdata;
            }
        } catch (FileNotFoundException var18) {
            return localdata;
        } catch (Exception var19) {
            return localdata;
        } finally {
            try {
                if(outStream != null) {
                    outStream.close();
                }

                if(inStream != null) {
                    inStream.close();
                }
            } catch (IOException var17) {
                ;
            }

        }

        return null;
    }

    public static void savePhotoData(byte[] data, String filePath) {
        BufferedOutputStream stream = null;
        File file = null;

        try {
            file = new File(filePath);
            FileOutputStream fstream = new FileOutputStream(file, false);
            stream = new BufferedOutputStream(fstream);
            stream.write(data);
        } catch (Exception var13) {
            ;
        } finally {
            if(stream != null) {
                try {
                    stream.close();
                } catch (Exception var12) {
                    ;
                }
            }

        }

    }

    public static byte[] Bitmap2Bytes(Bitmap bm) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        bm.compress(Bitmap.CompressFormat.JPEG, 80, baos);
        return baos.toByteArray();
    }

    public static Bitmap creatflipImage(Bitmap bmp) {
        Canvas canvas = new Canvas();
        Paint paint = new Paint();
        int LCD_WIDTH = bmp.getWidth();
        int LCD_HEIGHT = bmp.getHeight();
        Bitmap bitmap = Bitmap.createBitmap(LCD_WIDTH, LCD_HEIGHT, Bitmap.Config.ARGB_8888);
        canvas.setBitmap(bitmap);
        Camera camera = new Camera();
        Matrix matrix = new Matrix();
        camera.rotateY(180.0F);
        camera.getMatrix(matrix);
        matrix.postTranslate((float)LCD_WIDTH, 0.0F);
        canvas.save();
        canvas.drawBitmap(bmp, matrix, paint);
        canvas.restore();
        return bitmap;
    }

    public static int hexToInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value, 16);
        } catch (Exception var3) {
            return defaultValue;
        }
    }

    public static String encode(byte[] data) {
        StringBuffer sb = new StringBuffer();
        int len = data.length;
        int i = 0;

        while(i < len) {
            int b1 = data[i++] & 255;
            if(i == len) {
                sb.append(base64EncodeChars[b1 >>> 2]);
                sb.append(base64EncodeChars[(b1 & 3) << 4]);
                sb.append("==");
                break;
            }

            int b2 = data[i++] & 255;
            if(i == len) {
                sb.append(base64EncodeChars[b1 >>> 2]);
                sb.append(base64EncodeChars[(b1 & 3) << 4 | (b2 & 240) >>> 4]);
                sb.append(base64EncodeChars[(b2 & 15) << 2]);
                sb.append("=");
                break;
            }

            int b3 = data[i++] & 255;
            sb.append(base64EncodeChars[b1 >>> 2]);
            sb.append(base64EncodeChars[(b1 & 3) << 4 | (b2 & 240) >>> 4]);
            sb.append(base64EncodeChars[(b2 & 15) << 2 | (b3 & 192) >>> 6]);
            sb.append(base64EncodeChars[b3 & 63]);
        }

        return sb.toString();
    }

    public static byte[] decode(String str) {
        byte[] data = str.getBytes();
        int len = data.length;
        ByteArrayOutputStream buf = new ByteArrayOutputStream(len);
        int i = 0;

        while(i < len) {
            byte b1;
            do {
                b1 = base64DecodeChars[data[i++]];
            } while(i < len && b1 == -1);

            if(b1 == -1) {
                break;
            }

            byte b2;
            do {
                b2 = base64DecodeChars[data[i++]];
            } while(i < len && b2 == -1);

            if(b2 == -1) {
                break;
            }

            buf.write(b1 << 2 | (b2 & 48) >>> 4);

            byte b3;
            do {
                b3 = data[i++];
                if(b3 == 61) {
                    return buf.toByteArray();
                }

                b3 = base64DecodeChars[b3];
            } while(i < len && b3 == -1);

            if(b3 == -1) {
                break;
            }

            buf.write((b2 & 15) << 4 | (b3 & 60) >>> 2);

            byte b4;
            do {
                b4 = data[i++];
                if(b4 == 61) {
                    return buf.toByteArray();
                }

                b4 = base64DecodeChars[b4];
            } while(i < len && b4 == -1);

            if(b4 == -1) {
                break;
            }

            buf.write((b3 & 3) << 6 | b4);
        }

        return buf.toByteArray();
    }

    public static String addZeroForNum(String str, int strLength, boolean isLeft) {

        int strLen = str.length();
        if (strLen < strLength) {
            while (strLen < strLength) {
                StringBuffer sb = new StringBuffer();
                if (isLeft) {
                    sb.append("0").append(str);// 左补0
                } else {
                    sb.append(str).append("0");//右补0
                }
                str = sb.toString();
                strLen = str.length();
            }
        }

        return str;
    }
}
