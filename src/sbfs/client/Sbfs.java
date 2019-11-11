/*
 * Main class : handles command line arguments and client instanciation
 * Author: Sébastien Maes
 */
package sbfs.client;

import picocli.CommandLine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@CommandLine.Command(name = "sbfs", footer = "Copyright(c) 2019 Sébastien Maes",
        description = "Secure Basic File Sharer (SBFS) allows to easily get/send encrypted FILEs, " +
                "using AES-256 and RSA-2048 to respectively cipher the file and the secret key, from/to a host (aka a server)")
public class Sbfs {
    @CommandLine.Parameters(index = "0", paramLabel = "MODE", description = "The mode in which the program will operate (send/get).", arity = "1")
    public String mode;

    @CommandLine.Parameters(index = "1", paramLabel = "HOST", description = "IP Address from the host", arity = "1")
    public String strServer = "localhost";

    @CommandLine.Option(names = { "-f", "--file" }, description = "Name of the file to download (extension included) / Path to the file to send", required = true)
    public File file;

    @CommandLine.Option(names = {"-h", "--help"}, usageHelp = true, description = "Display this help and exit")
    public boolean helpRequested = false;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Sbfs app = new Sbfs();
        CommandLine cl = new CommandLine(app);
        cl.parseArgs(args);

        if (cl.isUsageHelpRequested()) {
            cl.usage(System.out);
            return;
        } else if (cl.isVersionHelpRequested()) {
            cl.printVersionHelp(System.out);
            return;
        }
        // App logic
        Client client = new Client(app);
        client.routine();

    }
}
