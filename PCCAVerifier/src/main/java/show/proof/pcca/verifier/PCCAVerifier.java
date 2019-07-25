package show.proof.pcca.verifier;

import java.io.InputStream;
import java.security.InvalidParameterException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import show.proof.pcca.verifier.lib.PCCACertVerifier;
import show.proof.pcca.verifier.lib.PCCAErrors;

/**
 * Provides the interface for verifying Proof-Carrying Certificates issued by
 * PCCA.
 *
 */
public class PCCAVerifier {
    /**
     * the certificate verifier object.
     */
    private PCCACertVerifier certVerifier = null;
    /**
     * the x509 certificate object.
     */
    private X509Certificate signerCert = null;

    /**
     * Constructor for PCCAVerifier
     * 
     * @param is             the input stream of certificate.
     * @param psesDataString the JSON string of PSES data.
     * @throws InvalidParameterException
     * @throws CertificateException
     */
    public PCCAVerifier(InputStream is, String psesDataString) throws InvalidParameterException, CertificateException {
        certVerifier = new PCCACertVerifier(is, psesDataString);
    }

    /**
     * Perform the verification procedure.
     * 
     * @return the error code of verification.
     */
    public PCCAErrors verify() {
        PCCAErrors result = certVerifier.verify();

        if (result == PCCAErrors.SUCCESS)
            signerCert = certVerifier.getCertificate();

        return result;
    }

    /**
     * Get the certificate subject.
     * 
     * @return the string of certificate subject.
     */
    public String getCertSubject() {
        if (signerCert == null)
            return "";
        else {
            return signerCert.getSubjectDN().getName().replaceAll("CN=", "");
        }
    }

    /**
     * Get the certificate key hash.
     * 
     * @return the HEX string of certificate key hash.
     */
    public String getCertKeyHash() {
        if (signerCert == null)
            return "";
        else {
            String result = "";
            byte[] subjKeyIdBuf = signerCert.getExtensionValue("2.5.29.14");

            // skip ASN1 structure
            subjKeyIdBuf = Arrays.copyOfRange(subjKeyIdBuf, 4, subjKeyIdBuf.length);

            for (int byteIdx = 0; byteIdx < subjKeyIdBuf.length; byteIdx++) {
                if (!result.isEmpty())
                    result += ":";

                result += Integer.toString((subjKeyIdBuf[byteIdx] & 0xff) + 0x100, 16).substring(1);
            }

            return result;
        }
    }

    /**
     * Get the not before date of certificate.
     * 
     * @return a formatted date string.
     */
    public String getCertNotBefore() {
        if (signerCert == null)
            return "";
        else
            return _printFormatDate(signerCert.getNotBefore());
    }

    /**
     * Get the not after date of certificate.
     * 
     * @return a formatted date string.
     */
    public String getCertNotAfter() {
        if (signerCert == null)
            return "";
        else
            return _printFormatDate(signerCert.getNotAfter());
    }

    /**
     * Format the date object to a string.
     * 
     * @param date the date object to be formatted.
     * @return a formatted date string.
     */
    private String _printFormatDate(Date date) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        return dateFormat.format(date);
    }
}
