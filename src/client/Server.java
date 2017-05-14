package client;

import org.apache.commons.io.IOUtils;
import util.CommonUtils;
import util.EncryptionUtils;
import util.KeyGenerator;
import util.message.MessageHeader;
import util.message.MessageWrapper;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Created by mayezhou on 2017/5/12.
 */
public class Server implements Runnable{
    public static PrivateKey SERVER_PRIVATE_KEY;
    public static PublicKey SERVER_PUBLIC_KEY;

    public Server() {
        init();
    }

    public static void init() {
        try {
            SERVER_PRIVATE_KEY = KeyGenerator.loadPrivateKey("assets/key/server.pri");
            SERVER_PUBLIC_KEY = KeyGenerator.loadPublicKey("assets/key/server.pub");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
            ServerSocket serverSocket = new ServerSocket(54321);
            while (true) {
                Socket client = serverSocket.accept();
                System.out.println("Server accepting");
                try {
                    ObjectInputStream in = new ObjectInputStream(client.getInputStream());
                    byte[] receivedBytes = (byte[]) in.readObject();
                    //handle REGISTER
                    MessageWrapper request = new MessageWrapper(receivedBytes, null, Server.SERVER_PRIVATE_KEY);
                    String username = request.getHeader().get("Username");
                    System.out.println("from:" + username);
                    //send response
                    KeyPair clientKeyPair = KeyGenerator.generateRSAKey();
                    String requestBody = EncryptionUtils.decryptWithRSA(request.getBody(), Server.SERVER_PRIVATE_KEY);
                    PublicKey clientPublicKey = (PublicKey) CommonUtils.byteArrayToObject(CommonUtils.stringToByteArray(requestBody));
                    byte[] responseBody = EncryptionUtils.encryptWithRSA(CommonUtils.objectToString(clientKeyPair), clientPublicKey);
                    MessageHeader header = new MessageHeader();
                    header
                            .add("Service", "register")
                            .add("Status", "200");
                    ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
                    out.writeObject((new MessageWrapper(header, responseBody, clientPublicKey, Server.SERVER_PRIVATE_KEY)).getWrappedData());
                    out.close();
                    in.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Thread serverThread = new Thread(new Server());
        serverThread.start();
    }
}
