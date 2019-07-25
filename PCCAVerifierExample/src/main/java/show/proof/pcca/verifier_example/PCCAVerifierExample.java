package show.proof.pcca.verifier_example;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

import show.proof.pcca.verifier.PCCAVerifier;
import show.proof.pcca.verifier.lib.PCCAErrors;

/**
 * Provides the example code for using PCCAVerifier.
 *
 */
public class PCCAVerifierExample {
    /**
     * the download URL path of PSES data.
     */
    final private static String psesDownloadURL = "https://download.ca.proof.show/PSES.json";
    /**
     * the result messages.
     */
    final private static String[] resultMessages = new String[] { "Successfully verify PCCA certificate.",
            "Invalid certificate format.", "Invalid mail \"subject\".", "Invalid mail \"to\".",
            "Invalid mail \"from\".", "Invalid mail \"date\".", "Invalid mail \"content-type\".", "Invalid mail body.",
            "Invalid mail DKIM signature." };

    /**
     * Main method of example code.
     * 
     * @param args program arguments
     */
    public static void main(String[] args) {
        if (args.length == 1) {
            try {
                // read certificate file
                String certPath = args[0];
                FileInputStream fis = new FileInputStream(certPath);

                // retrieve PSES data
                String psesDataString = _retrievePSES();

                // initiate PCCAVerifier object
                PCCAVerifier verifier = new PCCAVerifier(fis, psesDataString);

                // perform validation
                PCCAErrors result = verifier.verify();

                // print the result message
                System.out.println("PCCAVerifier Version "
                        + PCCAVerifierExample.class.getPackage().getImplementationVersion() + " - ProofShow Inc.");
                System.out.println("");
                System.out.println(resultMessages[result.ordinal()]);

                // print certificate information
                if (result == PCCAErrors.SUCCESS) {
                    System.out.println("");
                    System.out.println("  Certificate Subject:    " + verifier.getCertSubject());
                    System.out.println("  Certificate Key Hash:   " + verifier.getCertKeyHash());
                    System.out.println("  Certificate Not Before: " + verifier.getCertNotBefore());
                    System.out.println("  Certificate Not After:  " + verifier.getCertNotAfter());
                    System.out.println("");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else
            System.out.println("Invalid argument");
    }

    /**
     * Read all string by the reader object.
     * 
     * @param rd the reader object
     * @return the complete string data
     * @throws IOException
     */
    private static String _readAll(Reader rd) throws IOException {
        StringBuilder sb = new StringBuilder();
        int cp;
        while ((cp = rd.read()) != -1) {
            sb.append((char) cp);
        }
        return sb.toString();
    }

    /**
     * Retrieve the PSES data.
     * 
     * @return the JSON string of PSES data.
     * @throws MalformedURLException
     * @throws IOException
     */
    private static String _retrievePSES() throws MalformedURLException, IOException {
        InputStream is = new URL(psesDownloadURL).openStream();
        BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
        String jsonText = _readAll(rd);

        return jsonText;
    }
}
