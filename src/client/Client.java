package client;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * Created by mayezhou on 2017/5/11.
 */
public class Client {
    //store session key in memory
    private KeyStore keyStore;
    private char[] pwdToKey;
    private KeyStore.ProtectionParameter protectionParameter;
    public String username;
    private List<Client> friends;
    private final KeyPair keyPair;

    public Client(String username, String password, KeyPair keyPair) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        this.username = username;
        this.pwdToKey = password.toCharArray();
        keyStore = KeyStore.getInstance("JKS");
        // initialize keystore
        keyStore.load(null, pwdToKey);
        protectionParameter = new KeyStore.PasswordProtection(pwdToKey);
        this.keyPair = keyPair;
    }

    public Key getPublicKey() {
        return keyPair.getPublic();
    }

    public Key getSecretKey(String keyAlias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, protectionParameter);
        return keyEntry.getSecretKey();
    }

    public void saveSessionKey(String keyAlias, SecretKey key) throws KeyStoreException {
        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
        keyStore.setEntry(keyAlias, keyEntry, protectionParameter);
    }
}
