import android.annotation.TargetApi;
import android.os.Build;
import client.Client;
import org.apache.commons.io.IOUtils;
import util.EncryptionUtils;
import util.KeyGenerator;
import util.message.MessageHeader;
import util.message.MessageWrapper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.ISO_8859_1;


/**
 * Created by lifengshuang on 10/05/2017.
 */
public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, CertificateException, KeyStoreException {
        testMessageWrapper();
//        System.out.println(testMD5().length);
//        testByteStringConversion();
//        System.out.println(testSymmetricEncryption());
//        testFileTransition();
//        Socket socket;
//        String message = "Hello World";
//        try {
//            //client
//            socket = new Socket("127.0.0.1", 54321);
//            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
//            out.writeObject(message.getBytes());
//            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
//            Object object = in.readObject();
//            byte[] receivedBytes = (byte[]) object;
//            System.out.println(new String(receivedBytes));
//            socket.close();
//        } catch (UnknownHostException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (ClassNotFoundException e) {
//            e.printStackTrace();
//        }
    }

    private static byte[] testMD5() throws NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, IOException, SignatureException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(testMessageWrapper());
    }

    private static int testSymmetricEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, CertificateException, KeyStoreException {
        KeyPair initKeyPair = KeyGenerator.generateRSAKey();
        Client a = new Client("A", "A's password", initKeyPair);
        Key key = KeyGenerator.generateSymmetricKey();
        String testText = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";
        byte[] message = EncryptionUtils.symmetricEncrypt(testText, key);
        String decryptedText = EncryptionUtils.symmetricDecrypt(message, key);
        return testText.compareTo(decryptedText);
    }

    private static void testFileTransition() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyPair initKeyPair = KeyGenerator.generateRSAKey();
        Client a = new Client("A", "A's password", initKeyPair);
        Key key = KeyGenerator.generateSymmetricKey();
        byte[] message = EncryptionUtils.encryptFile("dblpxml.pdf", key);
        EncryptionUtils.decryptFile("decryptedFile.pdf", message, key);
    }

    private static byte[] testMessageWrapper() throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, SignatureException {

        // RSA Key generation
        KeyPair initKeyPair = KeyGenerator.generateRSAKey();

        // load keys
        PrivateKey privateKey = initKeyPair.getPrivate();
        PublicKey publicKey = initKeyPair.getPublic();

        // Test data
        String testText = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";
        byte[] messageBody = EncryptionUtils.encryptWithRSA(testText, privateKey);

        // Message Header.
        // Header with a very long message is also tested.
        MessageHeader header = new MessageHeader();
        header
                .add("Service", "register")
                .add("Body Encryption", "Private Key")
                .add("Name", "Alice");

        // logs before message wrapping
        System.out.println("==== Before Message wrapping ====");
        System.out.println(header);
        System.out.println("Plaintext: " + testText);
        System.out.println("Encrypted text (body):" + Arrays.toString(messageBody));

        // Wrap header and body to bytes.
        MessageWrapper wrapper1 = new MessageWrapper(header, messageBody, publicKey, privateKey);

        // Use Socket to send this message. It's fully encrypted.
        // Suppose client sends this message to server.
        byte[] wrappedMessage = wrapper1.getWrappedData();

        // Suppose server has received the wrapped message.
        // Decode the message to header and body.
        MessageWrapper wrapper2 = new MessageWrapper(wrappedMessage, publicKey, privateKey);

        System.out.println("\n\n==== After Message wrapping ====");
        System.out.println(wrapper2);

        String decryptedText = EncryptionUtils.decryptWithRSA(wrapper2.getBody(), publicKey);
        System.out.println("Decrypted Text: " + decryptedText);

        return wrappedMessage;
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    private static void testByteStringConversion() {
        byte[] bytes = new byte[]{123, 21, 32, 41, 54, 7, 86, -10, -11};
        System.out.println(Arrays.toString(bytes));
        String s = new String(bytes, ISO_8859_1);
        System.out.println(s);
        byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
        System.out.println(Arrays.toString(b));
    }
}
