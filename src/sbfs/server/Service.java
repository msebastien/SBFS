/*
 * Service class managing I/O operations on socket. Handles request and send responses to a client.
 * Author: Sébastien Maes
 */
package sbfs.server;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

import sbfs.Crypto;
import sbfs.LogType;
import sbfs.Utilities;
import sbfs.client.RequestType;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Service implements Runnable{
    protected Socket sock;

    public Service(Socket sock){
        this.sock = sock;
    }

    /**
     * Service (server instance) thread
     */
    @Override
    public void run() {
        try{
            while(sock.isConnected()){
                routine();
            }
            Utilities.LOG(LogType.SERVER, "Service Routine ended SUCCESSFULLY.");
        } catch(IOException e){
            System.err.println("Client has disconnected.");
        } catch(NoSuchAlgorithmException e){
            System.err.println("This algorithm does not exist.");
        } catch(NoSuchPaddingException e){
            System.err.println(e.getMessage());
        } catch(InvalidKeySpecException e){
            System.err.println("Invalid Key Spec : " + e.getMessage());
        } catch(InvalidKeyException e){
            System.err.println("Invalid Key.");
        } catch(InvalidAlgorithmParameterException e){
            System.err.println("Invalid Algorithm Parameter" + e.getMessage());
        } catch(IllegalBlockSizeException e){
            System.err.println("Illegal Block Size : " + e.getMessage());
        } catch(BadPaddingException e){
            System.err.println("Bad Padding : " + e.getMessage());
        }
    }

    /**
     * Get received request type
     * @return response code
     */
    private int getRequestType() throws IOException {
        InputStream is = sock.getInputStream();
        byte[] bytes = new byte[4];
        int ret = -1;
        if(is.read(bytes) >= 4){
            // Checks if it's a valid response code
            RequestType res = RequestType.from(ByteBuffer.wrap(bytes).getInt());
            if(res == RequestType.GET || res == RequestType.SEND || res == RequestType.GET_PUBLIC_KEY){
                ret = res.getValue();
            }
        }
        return ret;
    }

    /**
     * Handle and process requests
     * @param reqNum request code
     */
    public void handleRequest(int reqNum) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        DataInputStream dis = new DataInputStream(sock.getInputStream());
        RequestType request = RequestType.from(reqNum);

        // Frame
        int frameLength = dis.readInt();
        byte[] bytesReceived = new byte[frameLength];
        if(frameLength > 0){
            dis.read(bytesReceived);
        }

        Utilities.LOG(LogType.SERVER, "Bytes Received from " + sock.getInetAddress() + ": " + bytesReceived.length);

        ByteBuffer bb = ByteBuffer.wrap(bytesReceived);
        switch(request){
            case GET:
                // File name
                int fileNameLength = bb.getInt();
                byte[] fileName = new byte[fileNameLength];
                bb = bb.get(fileName);

                // Retrieve client public key
                byte[] pubKeyBytes = new byte[bb.remaining()];
                bb.get(pubKeyBytes);

                Utilities.LOG(LogType.SERVER, "Received Pub Key: " + Utilities.bytesToHex(pubKeyBytes));

                X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKey clientPubKey = factory.generatePublic(pkSpec);

                // Encrypt file with public key and send it to client if it exists in ServerData/upload/
                File file = new File(Server.SERVER_UPLOAD_PATH + new String(fileName));
                if(file.exists() && !file.isDirectory()){
                    File encFile = new File(Utilities.getEncryptedFilePath(file));
                    encFile.createNewFile();

                    // Encrypt file with Secret Key
                    SecretKey sk = Crypto.generateSecretKey();
                    Crypto.encryptFile(file, sk);

                    // Encrypt secret key with public key from client
                    byte[] encryptedKey = Crypto.encryptSecretKey(sk, clientPubKey);
                    Crypto.addKeyToFile(encFile, encryptedKey);

                    sendResponse(ResponseType.OK, request, encFile);
                } else {
                    sendResponse(ResponseType.UNAVAILABLE, request, null);
                }
                break;
            case SEND:
                // File name
                int fNameLength = bb.getInt();
                byte[] fName = new byte[fNameLength];
                bb = bb.get(fName);

                // Checksum
                byte[] checksum = new byte[32]; // SHA-256
                bb = bb.get(checksum);

                // Retrieve encrypted file bytes and write it to ServerData/download/
                byte[] encFileBytes = new byte[bb.remaining()];
                bb.get(encFileBytes);
                Utilities.writeFile(encFileBytes, Server.SERVER_DOWNLOAD_PATH + new String(fName));

                // Compare Checksum
                File downloadedFile = new File(Server.SERVER_DOWNLOAD_PATH + new String(fName));
                if( Arrays.equals(checksum, Utilities.getFileChecksum(downloadedFile)) ){
                    Utilities.LOG(LogType.INFO, "File checksum is OK");
                } else {
                    Utilities.LOG(LogType.INFO, "Checksum FAIL : The file is probably corrupted or incomplete");
                }

                Utilities.LOG(LogType.INFO, "Decrypting file...");

                Crypto.decryptFile(downloadedFile, Crypto.loadKeyPair(Server.KEYS_PATH).getPrivate());
                sendResponse(ResponseType.OK, request, null);
                break;
            case GET_PUBLIC_KEY:
                sendResponse(ResponseType.OK, request, null);
                break;
            default:
                Utilities.LOG(LogType.SERVER, "Unknown request received from " + sock.getInetAddress());
                sendResponse(ResponseType.NOT_RECEIVED, request, null);
                break;
        }
    }

    /**
     * Send response to client
     * @param res Response type
     * @param requestReceived received request type
     * @param file file to send (not mandatory)
     */
    public void sendResponse(ResponseType res, RequestType requestReceived, File file) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        OutputStream os = sock.getOutputStream();

        int resType = res.getValue();
        int frameLength = 0;
        byte[] frame;
        ByteBuffer bb;

        // Write response frame (header + data) to output stream
        switch(res) {
            case OK:
                switch(requestReceived){
                    case GET:
                        if(!Objects.isNull(file)){
                            // Frame data
                            byte[] fileName = file.getName().getBytes();
                            byte[] checksum = Utilities.getFileChecksum(file);
                            byte[] fileBytes = Files.readAllBytes(file.toPath());
                            frameLength = (Integer.SIZE / 8) + fileName.length + checksum.length + fileBytes.length;

                            Utilities.LOG(LogType.SERVER, "Sending GET response. Size= " + frameLength);

                            frame = new byte[frameLength + 2*(Integer.SIZE / 8)];
                            bb = ByteBuffer.wrap(frame);
                            os.write(bb.putInt(resType).putInt(frameLength).putInt(fileName.length).put(fileName).put(checksum).put(fileBytes).array());
                        } else {
                            Utilities.LOG(LogType.SERVER, "Error sending GET response : file is null.");
                        }
                        break;
                    case SEND:
                        frame = new byte[2*(Integer.SIZE / 8)];
                        bb = ByteBuffer.wrap(frame);
                        os.write(bb.putInt(resType).putInt(frameLength).array());
                        break;
                    case GET_PUBLIC_KEY:
                        byte[] pkBytes = Crypto.loadKeyPair(Server.KEYS_PATH).getPublic().getEncoded();

                        frameLength = pkBytes.length;
                        frame = new byte[frameLength + 2*(Integer.SIZE / 8)];
                        bb = ByteBuffer.wrap(frame);

                        os.write(bb.putInt(resType).putInt(frameLength).put(pkBytes).array());
                        break;
                    default:
                        break;
                }
                break;
            case UNAVAILABLE:
            case NOT_RECEIVED:
                frame = new byte[2*(Integer.SIZE / 8)];
                bb = ByteBuffer.wrap(frame);
                os.write(bb.putInt(resType).putInt(frameLength).array());
                break;
            default:
                break;
        }

    }

    /**
     * Server routine / logic
     */
    public void routine() throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        int reqType = getRequestType();
        Utilities.LOG(LogType.SERVER, "Type of Request received : " + RequestType.from(reqType).toString());
        handleRequest(reqType);
    }
}
