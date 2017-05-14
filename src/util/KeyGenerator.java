package util;

import org.apache.commons.io.IOUtils;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyGenerator {
    private static void storePublicKey(Key key, String filepath) throws IOException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                key.getEncoded());
        FileOutputStream fos = new FileOutputStream(filepath);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();
    }

    private static void storePrivateKey(Key key, String filepath) throws IOException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                key.getEncoded());
        FileOutputStream fos = new FileOutputStream(filepath);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public static Key generateSymmetricKey() throws NoSuchAlgorithmException, IOException {
        final javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair key = keyGen.generateKeyPair();
        return key;
    }

    public static KeyPair generateRSAKey(String privateKeyPath, String publicKeyPath) throws NoSuchAlgorithmException, IOException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair key = keyGen.generateKeyPair();
        storePublicKey(key.getPublic(), publicKeyPath);
        storePrivateKey(key.getPrivate(), privateKeyPath);
        return key;
    }

    public static PublicKey loadPublicKey(InputStream in) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = IOUtils.toByteArray(in);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(InputStream in) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = IOUtils.toByteArray(in);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey loadPublicKey(String publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = IOUtils.toByteArray(new FileInputStream(publicKeyPath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static Key loadSecretKey(String algorithm, String keyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = IOUtils.toByteArray(new FileInputStream(keyPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    public static PrivateKey loadPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return (PrivateKey) loadSecretKey("RSA", privateKeyPath);
    }

}
