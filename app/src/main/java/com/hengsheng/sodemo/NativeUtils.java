package com.hengsheng.sodemo;

import android.content.Context;

/**
 * Created by zhangb on 2018/7/24/024
 */

public class NativeUtils {
    static {
        System.loadLibrary("native-lib");
    }

    public static native String getKey(Context context);

    public static native String getIv(Context context);

    public static native String getMyName();
}
