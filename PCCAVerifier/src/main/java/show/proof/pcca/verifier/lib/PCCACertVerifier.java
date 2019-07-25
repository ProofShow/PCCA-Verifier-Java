package show.proof.pcca.verifier.lib;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import org.json.JSONObject;

/**
 * Provides the logic of certificate verification.
 * 
 */
public class PCCACertVerifier {
    /**
     * the constant value of certificate validity period.
     */
    final private int CERT_VALIDITY_PERIOD_SEC = 60;
    /**
     * the constant value for ASN1 structure to skip.
     */
    final private int ASN1_SKIP_OFFSET_8 = 8;
    /**
     * the OID value of certificate policy.
     */
    final private String CERT_POLICY_OID = "2.5.29.32";
    /**
     * the OID value of certificate AIA.
     */
    final private String CERT_AIA_OID = "1.3.6.1.5.5.7.1.1";
    /**
     * the OID value of certificate CRL distribution points.
     */
    final private String CERT_CRL_DIST_OID = "2.5.29.31";
    /**
     * the OID value of certificate proof.
     */
    final private String PROOF_EMAIL_OID = "1.3.6.1.4.1.51803.2.1";
    /**
     * the binary data of certificate policy with base64 encoding.
     */
    final private String CERT_POLICY_DATA = "BIHfMIHcMIHZBgorBgEEAYOUWwECMIHKMCUGCCsGAQUFBwIBFhlodHRwczovL2Nwcy5jYS5wcm9vZi5zaG93MIGgBggrBgEFBQcCAjCBkxqBkFRoaXMgQ2VydGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vY3AuY2EucHJvb2Yuc2hvdw==";
    /**
     * the binary data of certificate AIA with base64 encoding.
     */
    final private String CERT_AIA_DATA = "BEYwRDBCBggrBgEFBQcwAoY2aHR0cHM6Ly9kb3dubG9hZC5jYS5wcm9vZi5zaG93L2lzc3Vlci9pbnRlcm1lZGlhdGUucGVt";
    /**
     * the binary data of certificate CRL distribution points with base64 encoding.
     */
    final private String CERT_CRL_DIST_DATA = "BCswKTAnoCWgI4YhaHR0cHM6Ly9jcmwuY2EucHJvb2Yuc2hvdy92MS9maWxl";

    /**
     * the certificate object.
     */
    private X509Certificate certificate = null;
    /**
     * the certificate proof string.
     */
    private String emailProof = "";
    /**
     * the JSON object of PSES data.
     */
    private JSONObject psesData = null;

    /**
     * Constructor for PCCACertVerifier.
     * 
     * @param is             the input stream of certificate.
     * @param psesDataString the JSON string of PSES data.
     * @throws InvalidParameterException
     * @throws CertificateException
     */
    public PCCACertVerifier(InputStream is, String psesDataString)
            throws InvalidParameterException, CertificateException {

        // check the parameters
        if (is == null)
            throw new InvalidParameterException("invalid certificate input stream");

        if (psesDataString == null || psesDataString.isEmpty())
            throw new InvalidParameterException("invalid PSES data string");

        // generate certificate from input stream
        this.certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);

        // decode JSON string of PSES data
        this.psesData = new JSONObject(psesDataString);
    }

    /**
     * get the signer's certificate.
     * 
     * @return a certificate object.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Perform the verification procedure.
     * 
     * @return the error code of verification.
     */
    public PCCAErrors verify() {
        PCCAErrors result = PCCAErrors.UNKNOW;

        if (!_testCertFormat())
            result = PCCAErrors.INVALID_CERT_FORMAT;
        else
            result = _exeProofVerifier();

        return result;
    }

    /**
     * Test certificate serial number.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertSN() {
        BigInteger certSN = certificate.getSerialNumber();
        byte[] certSNBytes = certSN.toByteArray();

        return (certSN.bitLength() == 160 || (certSN.toByteArray().length == 20 && certSNBytes[0] != 0));
    }

    /**
     * Test certificate issuer.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertIssuer() {
        try {
            InputStream issuerCertStream = getClass().getResourceAsStream("/PCCAIntermediateCA.pem");
            X509Certificate issuerCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(issuerCertStream);

            certificate.verify(issuerCert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test certificate validity period.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertValidityPeriod() {
        long certNotBeforeTimestamp = certificate.getNotBefore().getTime() / 1000;
        long certNotAfterTimestamp = certificate.getNotAfter().getTime() / 1000;

        return ((certNotAfterTimestamp - certNotBeforeTimestamp) == CERT_VALIDITY_PERIOD_SEC);
    }

    /**
     * Test certificate BasicConstraints extension.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertBasicConstraints() {
        int certBC = certificate.getBasicConstraints();
        return (certBC == -1);
    }

    /**
     * Test certificate KeyUsave extension.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertKeyUsage() {
        boolean[] keyUsages = certificate.getKeyUsage();

        return (keyUsages[0] && keyUsages[1] && !keyUsages[2] && !keyUsages[3] && !keyUsages[4] && !keyUsages[5]
                && !keyUsages[6] && !keyUsages[7] && !keyUsages[8]);
    }

    /**
     * Test certificate Policy extension.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertPolicy() {
        byte[] certPolicyBytes = certificate.getExtensionValue(CERT_POLICY_OID);

        if (certPolicyBytes == null)
            return false;

        return Base64.getEncoder().encodeToString(certPolicyBytes).equals(CERT_POLICY_DATA);
    }

    /**
     * Test certificate AIA extension.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertAIA() {
        byte[] certAIABytes = certificate.getExtensionValue(CERT_AIA_OID);

        if (certAIABytes == null)
            return false;

        return Base64.getEncoder().encodeToString(certAIABytes).equals(CERT_AIA_DATA);
    }

    /**
     * Test certificate CRLDistributionPoints extension.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertCRLDist() {
        byte[] certCRLDistBytes = certificate.getExtensionValue(CERT_CRL_DIST_OID);

        if (certCRLDistBytes == null)
            return false;

        return Base64.getEncoder().encodeToString(certCRLDistBytes).equals(CERT_CRL_DIST_DATA);
    }

    /**
     * Test certificate key length.
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertKeyLen() {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey rsaPubkey = (RSAPublicKey) certificate.getPublicKey();

            return (rsaPubkey.getModulus().bitLength() == 2048);
        } else
            return false;
    }

    /**
     * Test existence of certificate proof
     * 
     * @return true if pass the testing.
     */
    private boolean _testEmailProof() {
        try {
            byte[] extensionBytes = certificate.getExtensionValue(PROOF_EMAIL_OID);

            if (extensionBytes == null)
                return false;

            byte[] emailProofB64Bytes = Arrays.copyOfRange(extensionBytes, ASN1_SKIP_OFFSET_8, extensionBytes.length);
            emailProof = new String(emailProofB64Bytes);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test certificate format
     * 
     * @return true if pass the testing.
     */
    private boolean _testCertFormat() {
        try {
            if (!_testCertSN())
                return false;
            else if (!_testCertIssuer())
                return false;
            else if (!_testCertValidityPeriod())
                return false;
            else if (!_testCertBasicConstraints())
                return false;
            else if (!_testCertKeyUsage())
                return false;
            else if (!_testCertPolicy())
                return false;
            else if (!_testCertAIA())
                return false;
            else if (!_testCertCRLDist())
                return false;
            else if (!_testCertKeyLen())
                return false;
            else if (!_testEmailProof())
                return false;
            else
                return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test certificate proof with ProofVerifier
     * 
     * @return the verification result code
     */
    private PCCAErrors _exeProofVerifier() {
        try {
            PCCAProofVerifier proofVerifier = new PCCAProofVerifier(certificate, Base64.getDecoder().decode(emailProof),
                    psesData);

            return proofVerifier.verify();
        } catch (Exception e) {
            return PCCAErrors.UNKNOW;
        }
    }
}