package util.message;

import android.annotation.TargetApi;
import android.os.Build;
import util.EncryptionUtils;
import util.CommonUtils;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * The public key is the receiver's public key.
 * Header and body are both encrypted message.
 */
public class MessageWrapper {

    private MessageHeader header;
    private byte[] body;
    private byte[] wrappedData;

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public MessageWrapper(MessageHeader header, byte[] body, PublicKey publicKey, PrivateKey privateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        this.header = header;
        this.body = body;
        byte[] encryptedHeader = EncryptionUtils.encryptWithRSA(header.toString(), publicKey);
        byte[] lengthBlock = EncryptionUtils.encryptWithRSA(String.valueOf(encryptedHeader.length), publicKey);
        byte[] dataWithoutSignature = new byte[lengthBlock.length + encryptedHeader.length + body.length];
        System.arraycopy(lengthBlock, 0, dataWithoutSignature, 0, lengthBlock.length);
        System.arraycopy(encryptedHeader, 0, dataWithoutSignature, lengthBlock.length, encryptedHeader.length);
        System.arraycopy(body, 0, dataWithoutSignature, lengthBlock.length + encryptedHeader.length, body.length);
        byte[] hash = MessageDigest.getInstance("MD5").digest(dataWithoutSignature);
        byte[] signature = EncryptionUtils.encryptWithRSA(CommonUtils.byteArrayToString(hash), privateKey);
        wrappedData = new byte[dataWithoutSignature.length + EncryptionUtils.BYTE_BLOCK_SIZE];
        System.arraycopy(dataWithoutSignature, 0, wrappedData, 0, dataWithoutSignature.length);
        System.arraycopy(signature, 0, wrappedData, dataWithoutSignature.length, EncryptionUtils.BYTE_BLOCK_SIZE);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public MessageWrapper(byte[] wrappedData, PublicKey publicKey, Key privateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        this.wrappedData = wrappedData;
        byte[] dataWithoutSignature = Arrays.copyOfRange(wrappedData, 0, wrappedData.length - EncryptionUtils.BYTE_BLOCK_SIZE);
        // publicKey == null means don't check the signature
        if (publicKey != null) {
            byte[] signatureBlock = Arrays.copyOfRange(wrappedData, dataWithoutSignature.length, wrappedData.length);
            byte[] hash = MessageDigest.getInstance("MD5").digest(dataWithoutSignature);
            byte[] hashFromSignature = CommonUtils.stringToByteArray(EncryptionUtils.decryptWithRSA(signatureBlock, publicKey));
            if (!Arrays.equals(hash, hashFromSignature)) {
                throw new SignatureException();
            }
        }
        byte[] lengthBlock = Arrays.copyOfRange(dataWithoutSignature, 0, EncryptionUtils.BYTE_BLOCK_SIZE);
        int headerLength = Integer.parseInt(EncryptionUtils.decryptWithRSA(lengthBlock, privateKey));
        byte[] encryptedHeader = Arrays.copyOfRange(dataWithoutSignature, EncryptionUtils.BYTE_BLOCK_SIZE, EncryptionUtils.BYTE_BLOCK_SIZE + headerLength);
        this.header = MessageHeader.parse(EncryptionUtils.decryptWithRSA(encryptedHeader, privateKey));
        this.body = Arrays.copyOfRange(dataWithoutSignature, EncryptionUtils.BYTE_BLOCK_SIZE + headerLength, dataWithoutSignature.length);
    }

    public MessageHeader getHeader() {
        return header;
    }

    public byte[] getBody() {
        return body;
    }

    public byte[] getWrappedData() {
        return wrappedData;
    }

    @Override
    public String toString() {
        return "The header is " + this.header + "\nThe body is " + Arrays.toString(this.body);
    }
}
