package com.bhz.xinduncard;

/**
 * Created by hu on 2018/1/25.
 */

public class SM4_Context {
    public int mode = 1;
    public long[] sk = new long[32];
    public boolean isPadding = true;

    public SM4_Context() {
    }
}
