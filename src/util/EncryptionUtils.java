package util;

import org.apache.commons.io.IOUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

/**
 * Created by lifengshuang on 09/05/2017.
 */
public class EncryptionUtils {

    public final static int STRING_BLOCK_SIZE = 245;
    public final static int BYTE_BLOCK_SIZE = 256;

    public static byte[] symmetricEncrypt(String text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text.getBytes());
    }

    public static byte[] encryptFile(String filepath, Key key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] data = IOUtils.toByteArray(new FileInputStream(filepath));
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static void decryptFile(String filepath, byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        FileOutputStream fos = new FileOutputStream(filepath);
        fos.write(cipher.doFinal(data));
        fos.close();
    }

    public static String symmetricDecrypt(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(data));
    }

    public static byte[] encryptWithRSA(String text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int blocks = (text.length() + STRING_BLOCK_SIZE - 1) / STRING_BLOCK_SIZE;
        byte[] result = new byte[BYTE_BLOCK_SIZE * blocks];
        for (int i = 0; i < blocks; i++) {
            String textBlock = text.substring(i * STRING_BLOCK_SIZE, Math.min((i + 1) * STRING_BLOCK_SIZE, text.length()));
            byte[] dataBlock = cipher.doFinal(CommonUtils.stringToByteArray(textBlock));
            System.arraycopy(dataBlock, 0, result, i * BYTE_BLOCK_SIZE, BYTE_BLOCK_SIZE);
        }
        return result;
    }

    public static String decryptWithRSA(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        int blocks = (data.length + BYTE_BLOCK_SIZE - 1) / BYTE_BLOCK_SIZE;
        String result = "";
        for (int i = 0; i < blocks; i++) {
            byte[] dataBlock = Arrays.copyOfRange(data, i * BYTE_BLOCK_SIZE, (i + 1) * BYTE_BLOCK_SIZE);
            String textBlock = CommonUtils.byteArrayToString(cipher.doFinal(dataBlock));
            result += textBlock;
        }
        return result;
    }

}
