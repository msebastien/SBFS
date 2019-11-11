package sbfs;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.util.Date;

public class Utilities {
    public static String bytesToHex(byte[] input){
        String str = "";
        for (byte b : input) {
            str += String.format("%02X", b);
        }
        return str;
    }

    public static void LOG(LogType type, String message){
        String prefix = "";
        switch(type){
            case INFO:
                prefix = "[INFO] ";
                break;
            case CLIENT:
                prefix = "[CLIENT] ";
                break;
            case SERVER:
                prefix = "[SERVER] ";
                break;
            case DATA:
                prefix = "[DATA] ";
                break;
            default:
                break;
        }
        System.out.println(prefix + message);

        DateFormat df = DateFormat.getDateTimeInstance();
        Date date = new Date();
        writeFile((df.format(date) + " " + prefix + message + "\n").getBytes(), "logs.txt", true);
    }

    public static void writeFile(byte[] data, String path) {
        try{
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(data);
            fos.close();
        } catch(FileNotFoundException e){
            System.err.println("File not found.");
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public static void writeFile(byte[] data, String path, boolean append) {
        try{
            FileOutputStream fos = new FileOutputStream(path, append);
            fos.write(data);
            fos.close();
        } catch(FileNotFoundException e){
            System.err.println("File not found.");
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public static byte[] getFileChecksum(File file) throws NoSuchAlgorithmException, IOException {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            byte[] byteArray = new byte[1024];
            int bytesCount = 0;

            while((bytesCount = fis.read(byteArray)) != -1){
                messageDigest.update(byteArray, 0, bytesCount);
            }

            fis.close();
        return messageDigest.digest();
    }
    // Get file path for encrypted version of a plain file
    public static String getEncryptedFilePath(File plainFile){
        String[] filePath = plainFile.getPath().split("[.]");
        return filePath[0] + ".enc." + filePath[1];
    }

    // Get file path for decrypted version of a ciphered file
    public static String getDecryptedFilePath(File cipheredFile){
        String[] filePath = cipheredFile.getPath().split("[.]");
        if(filePath.length > 2){
            return filePath[0] + ".dec." + filePath[2];
        } else{
            return filePath[0] + ".dec." + filePath[1];
        }
    }
}
