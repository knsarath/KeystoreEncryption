package com.app.sample.keystoreencryption;

import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * A wrapper class for logging
 */

public class LogUtils {

    private static final String TAG = LogUtils.class.getSimpleName();
    public static final boolean ENABLE_LOG = true;

    public static void LOGD(final String tag, String message) {
        if (ENABLE_LOG) {
            Log.d(tag, message);
        }
    }

    public static void LOGD(final Object tagclass, String message) {
        if (ENABLE_LOG) {
            Log.d(tagclass.getClass().getSimpleName(), message);
        }
    }

    public static void LOGV(final String tag, String message) {
        if (ENABLE_LOG) {
            Log.v(tag, message);
        }
    }

    public static void LOGI(final String tag, String message) {
        Log.i(tag, message);
    }

    public static void LOGW(final String tag, String message) {
        Log.w(tag, message);
    }

    public static void LOGE(final String tag, String message) {
        if (ENABLE_LOG) {
            Log.e(tag, message);
        }
    }

    public static void LOGE(final Object tag, String message) {
        LOGE(tag.getClass().getSimpleName(), message);
    }

    private LogUtils() {
    }

    public static void writeToFile(String directoryName, String fileName, String body) throws IOException {
        FileOutputStream fos;
        final File dir = new File(directoryName);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        final File file = new File(dir, fileName);
        if (!file.exists()) {
            file.createNewFile();
        }
        fos = new FileOutputStream(file, true);
        fos.write(body.getBytes());
        fos.close();
    }
}
