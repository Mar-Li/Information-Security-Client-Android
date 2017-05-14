package com.example.test;

import android.app.Activity;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import client.Client;
import client.Server;
import util.CommonUtils;
import util.EncryptionUtils;
import util.KeyGenerator;
import util.message.MessageHeader;
import util.message.MessageWrapper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class MainActivity extends Activity {
    private final String DEBUG_TAG = "RegisterActivity";
    private EditText usernameComp;
    private EditText emailComp;
    private EditText pwdComp;
    private Button mButton;

    /**
     * Called when the activity is first created.
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        //force to connect in socket in main thread
        if (android.os.Build.VERSION.SDK_INT > 9) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }
        usernameComp = (EditText) findViewById(R.id.username);
        emailComp = (EditText) findViewById(R.id.email);
        pwdComp = (EditText) findViewById(R.id.password);
        mButton = (Button) findViewById(R.id.button);
        mButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Socket socket;
                String username = usernameComp.getText().toString();
                String email = emailComp.getText().toString();
                String password = pwdComp.getText().toString();
                try {
                    KeyPair initKeyPair = KeyGenerator.generateRSAKey();
                    AssetManager assetManager = getAssets();
                    PublicKey serverPublicKey = KeyGenerator.loadPublicKey(assetManager.open("key/server.pub"));
                    //encrypt message
                    MessageHeader messageHeader = new MessageHeader();
                    messageHeader
                            .add("Service", "register")
                            .add("Username", username);
                    byte[] body = EncryptionUtils.encryptWithRSA(CommonUtils.objectToString(initKeyPair.getPublic()), serverPublicKey);
                    Log.d(DEBUG_TAG, Arrays.toString(body));
                    MessageWrapper request = new MessageWrapper(messageHeader, body, serverPublicKey, initKeyPair.getPrivate());
                    Log.d(DEBUG_TAG, request.toString());
                    //connect to server
                    try {
                        socket = new Socket("192.168.1.18", 54321);//TODO: ip update
                        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                        out.writeObject(request.getWrappedData());
                        //get response
                        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                        Object object = in.readObject();
                        byte[] receivedBytes = (byte[]) object;
                        MessageWrapper response = new MessageWrapper(receivedBytes, serverPublicKey, initKeyPair.getPrivate());
                        //parse response
                        String status = response.getHeader().get("status");
                        if (status.equals("200")) {
                            Log.i(DEBUG_TAG, "register success, get correct response from server");
                            byte[] encryptedBody = response.getBody();
                            String decrypedBody = EncryptionUtils.decryptWithRSA(encryptedBody, serverPublicKey);
                            //get true RSA keypair
                            KeyPair myKeyPair = (KeyPair) CommonUtils.byteArrayToObject(CommonUtils.stringToByteArray(decrypedBody));
                            Client client = new Client(username, password, myKeyPair);//TODO: extract outside
                            Log.i(DEBUG_TAG, "register done, create client " + client.username);
                        }
                        socket.close();
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    } catch (SignatureException e) {
                        e.printStackTrace();
                    }
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
            }
        });
    }

}
