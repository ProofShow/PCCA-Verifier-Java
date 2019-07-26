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
import show.proof.pcca.verifier.lib.PCCAVerifierReport;

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
     * @return the report data of verification.
     */
    public PCCAVerifierReport verify() {
        PCCAVerifierReport report = new PCCAVerifierReport();
        report.retCode = certVerifier.verify();

        if (report.retCode == PCCAErrors.SUCCESS) {
            X509Certificate cert = certVerifier.getCertificate();

            report.certSubject = _getCertSubject(cert);
            report.certKeyHash = _getCertKeyHash(cert);
            report.certNotBefore = _getCertNotBefore(cert);
            report.certNotAfter = _getCertNotAfter(cert);
        }

        return report;
    }

    /**
     * Get the certificate subject.
     * 
     * @param cert the certificate to parse
     * @return the string of certificate subject.
     */
    private String _getCertSubject(X509Certificate cert) {
        if (cert == null)
            return "";
        else {
            return cert.getSubjectDN().getName().replaceAll("CN=", "");
        }
    }

    /**
     * Get the certificate key hash.
     * 
     * @param cert the certificate to parse
     * @return the HEX string of certificate key hash.
     */
    private String _getCertKeyHash(X509Certificate cert) {
        if (cert == null)
            return "";
        else {
            String result = "";
            byte[] subjKeyIdBuf = cert.getExtensionValue("2.5.29.14");

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
     * @param cert the certificate to parse
     * @return a formatted date string.
     */
    private String _getCertNotBefore(X509Certificate cert) {
        if (cert == null)
            return "";
        else
            return _printFormatDate(cert.getNotBefore());
    }

    /**
     * Get the not after date of certificate.
     * 
     * @param cert the certificate to parse
     * @return a formatted date string.
     */
    private String _getCertNotAfter(X509Certificate cert) {
        if (cert == null)
            return "";
        else
            return _printFormatDate(cert.getNotAfter());
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
