package util;

import android.annotation.TargetApi;
import android.os.Build;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Created by lifengshuang on 13/05/2017.
 */
public class CommonUtils {

    public static byte[] objectToByteArray(Object object) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(object);
        byte[] result = bos.toByteArray();
        out.close();
        bos.close();
        return result;
    }

    public static String objectToString(Object object) throws IOException {
        return byteArrayToString(objectToByteArray(object));
    }

    public static Object byteArrayToObject(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = new ObjectInputStream(bis);
        return in.readObject();
    }

    public static Object stringToObject(String string) throws IOException, ClassNotFoundException {
        return byteArrayToObject(stringToByteArray(string));
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public static String byteArrayToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public static byte[] stringToByteArray(String string) {
        return string.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static byte[] readAllBytesFromInputStream(InputStream inputStream) throws IOException {
        BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int size;
        while ((size = bufferedInputStream.read(buf)) != -1) {
            outputStream.write(buf, 0, size);
        }
        return outputStream.toByteArray();
    }

}
