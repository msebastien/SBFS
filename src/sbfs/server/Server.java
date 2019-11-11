/*
 * Server class responsible for creating services (server instances) to communicate with multiple clients simultaneously
 * Author: Sébastien Maes
 */
package sbfs.server;

import sbfs.Crypto;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class Server implements Runnable {
    protected ServerSocket sockSvr;

    static int RSA_KEYS_SIZE = 2048;
    static String SERVER_PATH = "ServerData";
    static String SERVER_DOWNLOAD_PATH = SERVER_PATH + "/download/";
    static String SERVER_UPLOAD_PATH = SERVER_PATH + "/upload/";
    static String KEYS_PATH = SERVER_PATH + "/keys";

    /**
     * Initialize server
     */
    public void serve() {
        try {
            sockSvr = new ServerSocket(1555); // ServerSocket instance => a Socket instance is created for each connected client
            System.out.println("Press Enter to quit.");
            Thread thr = new Thread(this);
            thr.start(); // Starts server thread
            System.in.read();
            sockSvr.close();
        } catch(IOException e){
            System.err.println("Busy port");
        }

    }

    /**
     * Server thread
     */
    @Override
    public void run() {
        try{
            while(true) {
                Socket sock = sockSvr.accept(); // Listens on the port waiting for a connection to be made with a client. (Blocking)
                Service service = new Service(sock);
                Thread thr = new Thread(service); // Manage I/O operations on the socket
                thr.start();
            }
        } catch(IOException e){
            System.err.println(e.getMessage());
        }
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Crypto.generateKeyPair(Server.KEYS_PATH, RSA_KEYS_SIZE);
        Files.createDirectories(Paths.get(SERVER_DOWNLOAD_PATH));
        Files.createDirectories(Paths.get(SERVER_UPLOAD_PATH));

        Server server = new Server();
        server.serve();
    }
}
