/*
 * Client class that allows to communicate with a server. Send requests and handles server responses.
 * Author: Sébastien Maes
 */
package sbfs.client;

import sbfs.server.ResponseType;
import sbfs.*;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Client {
    private Socket sock;
    private App app;

    static int RSA_KEYS_SIZE = 2048;
    static String CLIENT_PATH = "ClientData";
    static String CLIENT_DOWNLOAD_PATH = CLIENT_PATH + "/download/";
    static String KEYS_PATH = CLIENT_PATH + "/keys";
    static int TRY_COUNT = 3;

    public Client(App app) throws IOException {
        this.app = app;
        this.sock = new Socket(); // Create a socket
        InetAddress addr = InetAddress.getByName(app.strServer); // Determines the IP Address of a host, given the host's name
        sock.connect(new InetSocketAddress(addr, 1555), 3000);
        sock.setSoTimeout(3000);
    }

    /**
     * Send request and handle response to get server's public key
     */
    private void getPublicKey() throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        RequestType execRequest = RequestType.GET_PUBLIC_KEY;
        sendRequest(execRequest);

        int response = getResponseType();
        handleResponse(response, execRequest);
    }

    /**
     * Get the received response type
     */
    private int getResponseType() throws IOException {
        DataInputStream dis = new DataInputStream(sock.getInputStream());
        byte[] bytes = new byte[4];
        int ret = -1;
        if(dis.read(bytes) >= 4){
            // Checks if it's a valid response code
            ResponseType res = ResponseType.from(ByteBuffer.wrap(bytes).getInt());
            if(res == ResponseType.OK || res == ResponseType.UNAVAILABLE || res == ResponseType.NOT_RECEIVED){
                ret = res.getValue();
            }
        }
        return ret;
    }

    /**
     * Send a type of request to the server
     * @param req The type of request to send (enum)
     */
    private void sendRequest(RequestType req) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        OutputStream os = sock.getOutputStream();

        // Header
        int reqType = req.getValue();
        int frameLength = 0;
        int fileNameLength = app.file.getName().getBytes().length;
        byte[] fileName = app.file.getName().getBytes();

        byte[] frame;
        ByteBuffer bb;

        // Write request frame (header + data) to output stream
        switch(req){
            case GET:
                Utilities.LOG(LogType.CLIENT, "Getting file from " + sock.getInetAddress());

                byte[] pubKey = Crypto.loadKeyPair(KEYS_PATH).getPublic().getEncoded();
                Utilities.LOG(LogType.CLIENT, "Sent Pub Key: " + Utilities.bytesToHex(pubKey));

                frameLength = (Integer.SIZE / 8) + fileName.length + pubKey.length;
                frame = new byte[frameLength + (2* Integer.SIZE / 8)];
                System.out.println("Empty frame size: " + frame.length);
                bb = ByteBuffer.wrap(frame);

                os.write(bb.putInt(reqType).putInt(frameLength).putInt(fileNameLength).put(fileName).put(pubKey).array());
                break;
            case SEND:
                System.out.println("Sending file to " + sock.getInetAddress());
                // Retrieve public key
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                getPublicKey();
                byte[] pkBytes = Files.readAllBytes(Paths.get(CLIENT_DOWNLOAD_PATH + "server_public.key"));

                X509EncodedKeySpec spec = new X509EncodedKeySpec(pkBytes);
                PublicKey serverPk = keyFactory.generatePublic(spec);

                // Encrypt file with Secret Key
                SecretKey sk = Crypto.generateSecretKey();
                Crypto.encryptFile(app.file, sk);

                // Encrypt secret key with public key from server
                byte[] encryptedKey = Crypto.encryptSecretKey(sk, serverPk);

                // Add encrypted key to file + compute checksum
                File encFile = new File(Utilities.getEncryptedFilePath(app.file));
                Crypto.addKeyToFile(encFile, encryptedKey);
                byte[] checksum = Utilities.getFileChecksum(encFile); // SHA-256 checksum (32 bytes)
                byte[] encFileBytes = Files.readAllBytes(encFile.toPath());

                frameLength = (Integer.SIZE / 8) + fileName.length + checksum.length + encFileBytes.length;
                frame = new byte[frameLength + 2* (Integer.SIZE / 8)];
                bb = ByteBuffer.wrap(frame);
                os.write(bb.putInt(reqType).putInt(frameLength).putInt(fileNameLength).put(fileName).put(checksum).put(encFileBytes).array());
                break;
            case GET_PUBLIC_KEY:
                frame = new byte[2* (Integer.SIZE / 8)];
                bb = ByteBuffer.wrap(frame);
                os.write(bb.putInt(reqType).putInt(frameLength).array());
                break;
            default:
                Utilities.LOG(LogType.CLIENT, "Bad Request");
                break;
        }
    }

    /**
     * Handle a response to a request.
     * @param res Type of response received
     * @param executedRequest Previously executed request
     */
    private void handleResponse(int res, RequestType executedRequest) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        DataInputStream dis = new DataInputStream(sock.getInputStream());
        ResponseType response = ResponseType.from(res);

        // Frame
        int frameLength = dis.readInt();
        byte[] bytesReceived = new byte[frameLength];
        if(frameLength > 0){
            dis.read(bytesReceived);
        }

        Utilities.LOG(LogType.CLIENT, "Bytes received from server. Size= " + bytesReceived.length);

        ByteBuffer bb = ByteBuffer.wrap(bytesReceived);

        switch(response) {
            case OK:
                switch(executedRequest){
                    case GET:
                        // File name
                        int fileNameLength = bb.getInt();
                        byte[] fileNameBytes = new byte[fileNameLength];
                        bb = bb.get(fileNameBytes);
                        String fileName = new String(fileNameBytes);

                        // Checksum
                        byte[] checksumBytes = new byte[32]; // SHA-256
                        bb = bb.get(checksumBytes);

                        // Write downloaded encrypted file
                        byte[] fileBytes = new byte[bb.remaining()];
                        bb.get(fileBytes);
                        String downloadedFilePath = CLIENT_DOWNLOAD_PATH + fileName;
                        Utilities.writeFile(fileBytes, downloadedFilePath);

                        // Compare Checksum
                        if( Arrays.equals(checksumBytes, Utilities.getFileChecksum(new File(downloadedFilePath))) ){
                            Utilities.LOG(LogType.CLIENT, "File checksum is OK");
                        } else {
                            Utilities.LOG(LogType.CLIENT, "Checksum FAIL : The file is probably corrupted or incomplete");
                        }

                        // Decrypt downloaded file
                        Crypto.decryptFile(new File(downloadedFilePath), Crypto.loadKeyPair(KEYS_PATH).getPrivate());
                        break;
                    case SEND:
                        Utilities.LOG(LogType.CLIENT, "The file has been successfully sent to the host.");
                        break;
                    case GET_PUBLIC_KEY:
                        Utilities.writeFile(bb.array(),CLIENT_DOWNLOAD_PATH + "server_public.key");
                    default:
                        break;
                }
                break;
            case UNAVAILABLE:
                Utilities.LOG(LogType.CLIENT, "Resource UNAVAILABLE.");
                break;
            case NOT_RECEIVED:
                Utilities.LOG(LogType.CLIENT, "Request NOT RECEIVED by the server.");
                break;
            default:
                Utilities.LOG(LogType.CLIENT, "Invalid response.");
                break;
        }
    }

    /**
     * Client routine / logic
     */
    public void routine() throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        Crypto.generateKeyPair(KEYS_PATH, RSA_KEYS_SIZE);
        Files.createDirectories(Paths.get(CLIENT_DOWNLOAD_PATH));

        int response = -1, count = 0;
        RequestType reqType = RequestType.NONE;
        do {
            if(app.mode.equalsIgnoreCase("get")){
                reqType = RequestType.GET;
                sendRequest(reqType);
                response = getResponseType();
                count++;
            } else if(app.mode.equalsIgnoreCase("send")){
                reqType = RequestType.SEND;
                sendRequest(RequestType.SEND);
                response = getResponseType();
                count++;
            } else {
                System.err.println(app.mode + " is not a valid mode. Please choose GET or SEND");
                System.exit(1);
            }
            handleResponse(response, reqType);
        } while((response == -1 || ResponseType.from(response) != ResponseType.OK) && count < TRY_COUNT);

        sock.close();

        Utilities.LOG(LogType.CLIENT, "Client Routine ended SUCCESSFULLY.");
    }
}
