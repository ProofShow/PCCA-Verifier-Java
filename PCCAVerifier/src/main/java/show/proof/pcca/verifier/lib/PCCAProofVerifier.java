package show.proof.pcca.verifier.lib;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.InvalidParameterException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

import javax.mail.Address;
import javax.mail.internet.InternetAddress;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.mail.util.MimeMessageParser;
import org.apache.commons.mail.util.MimeMessageUtils;
import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Provides the logic of certificate proof verification.
 *
 */
public class PCCAProofVerifier {
    /**
     * the constant value of email proof subject.
     */
    final private String MAIL_SUBJECT = "Certificate Signing Request in accordance with PCCA Subscriber Agreement";
    /**
     * the constant value of email proof receiver.
     */
    final private String MAIL_RECEIVER = "csr@ca.proof.show";
    /**
     * the constant value of email proof content type.
     */
    final private String MAIL_CONTENTTYPE = "text/plain";
    /**
     * the constant value of email proof body prefix.
     */
    final private String MAIL_BODYPREFIX = "-----BEGIN CERTIFICATE REQUEST-----";
    /**
     * the constant value of email proof body postfix.
     */
    final private String MAIL_BODYPOSTFIX = "-----END CERTIFICATE REQUEST-----";

    /**
     * the certificate object.
     */
    private X509Certificate certificate = null;
    /**
     * the byte array of certificate proof.
     */
    private byte[] mailMsg = null;
    /**
     * the email parser object for certificate proof.
     */
    private MimeMessageParser mailParser = null;
    /**
     * the CSR object.
     */
    private PKCS10CertificationRequest csr = null;
    /**
     * the JSON object of PSES data.
     */
    private JSONObject psesData = null;

    /**
     * Provides the function to retrieve DKIM key from PSES data.
     * 
     */
    private static class PSESDKIMKeyRetriever implements PublicKeyRecordRetriever {
        /**
         * the format rule for date object.
         */
        final private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        private boolean dkimRetrieveDone = false;
        private JSONObject psesData = null;
        private Date sendDate = null;

        /**
         * Constructor for PSESDKIMKeyRetriever
         * 
         * @param psesData the JSON object of PSES data.
         * @param sendDate the sending date of email proof.
         */
        public PSESDKIMKeyRetriever(JSONObject psesData, Date sendDate) {
            dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            this.psesData = psesData;
            this.sendDate = sendDate;
        }

        public List<String> getRecords(CharSequence methodAndOptions, CharSequence selector, CharSequence token)
                throws TempFailException, PermFailException {
            if ("dns/txt".equals(methodAndOptions)) {
                List<String> res = new LinkedList<String>();
                JSONObject domainObject = psesData.optJSONObject(token.toString());

                // set dkimRetrieveDone if no matched domain
                if (domainObject == null)
                    dkimRetrieveDone = true;
                else {
                    JSONArray dkimKeyList = domainObject.optJSONArray("DKIM Keys");

                    // set dkimRetrieveDone if no DKIM key can be retrieve
                    if (dkimKeyList == null || dkimKeyList.length() == 0)
                        dkimRetrieveDone = true;
                    else {
                        try {
                            // retrieve the first DKIM key
                            JSONObject dkimKey = dkimKeyList.getJSONObject(0);
                            dkimKeyList.remove(0);

                            // check the DKIM selector
                            if (selector.length() > 0
                                    && selector.toString().equals(dkimKey.optString("DNS Selector"))) {
                                String notBeforeDateStr = dkimKey.optString("Not Before");
                                String notAfterDateStr = dkimKey.optString("Not After");

                                // check the DKIM key not before date
                                if (notBeforeDateStr.length() > 0) {
                                    Date notBeforeDate = dateFormat.parse(notBeforeDateStr);

                                    if (sendDate.getTime() >= notBeforeDate.getTime()) {

                                        // check the DKIM key not after date
                                        if (notAfterDateStr.length() == 0)
                                            res.add("p=" + dkimKey.getString("Public Key"));
                                        else {
                                            Date notAfterDate = dateFormat.parse(notAfterDateStr);
                                            Calendar cal = Calendar.getInstance();

                                            cal.setTimeZone(TimeZone.getTimeZone("UTC"));
                                            cal.setTime(notAfterDate);
                                            cal.set(Calendar.HOUR_OF_DAY, 23);
                                            cal.set(Calendar.MINUTE, 59);
                                            cal.set(Calendar.SECOND, 59);
                                            cal.set(Calendar.MILLISECOND, 999);

                                            if (cal.getTime().getTime() >= sendDate.getTime())
                                                res.add("p=" + dkimKey.getString("Public Key"));
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                        }
                    }
                }

                return res;
            } else
                throw new PermFailException("Unsupported method");
        }

        public boolean isRetrieveDone() {
            return dkimRetrieveDone;
        }
    }

    /**
     * Constructor for PCCAProofVerifier.
     * 
     * @param certificate the certificate object.
     * @param mailMsg     the email proof of certificate.
     * @param psesData    the JSON object of PSES data.
     * @throws Exception
     */
    public PCCAProofVerifier(X509Certificate certificate, byte[] mailMsg, JSONObject psesData) throws Exception {

        // check parameters
        if (certificate == null)
            throw new InvalidParameterException("invalid certificate");

        if (mailMsg == null)
            throw new InvalidParameterException("invalid mail message");

        if (psesData == null)
            throw new InvalidParameterException("invalid PSES data");

        this.certificate = certificate;
        this.mailMsg = mailMsg;
        this.mailParser = new MimeMessageParser(MimeMessageUtils.createMimeMessage(null, this.mailMsg)).parse();
        this.psesData = new JSONObject(psesData.toString());
    }

    /**
     * Perform the verification procedure.
     * 
     * @return the error code of verification.
     */
    public PCCAErrors verify() {
        if (!_testMailSubject())
            return PCCAErrors.INVALID_MAIL_SUBJECT;
        else if (!_testMailTo())
            return PCCAErrors.INVALID_MAIL_TO;
        else if (!_testMailFrom())
            return PCCAErrors.INVALID_MAIL_FROM;
        else if (!_testMailDate())
            return PCCAErrors.INVALID_MAIL_DATE;
        else if (!_testMailContentType())
            return PCCAErrors.INVALID_MAIL_CONTENTTYPE;
        else if (!_testMailBody())
            return PCCAErrors.INVALID_MAIL_BODY;
        else if (!_testDKIM())
            return PCCAErrors.INVALID_MAIL_DKIM;
        else
            return PCCAErrors.SUCCESS;
    }

    /**
     * Test email subject.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailSubject() {
        try {
            String subject = mailParser.getSubject();

            subject = subject.trim().replaceAll("\\s{2,}", " ");
            return subject.equals(MAIL_SUBJECT);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test email "To" header.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailTo() {
        try {
            List<Address> mailToList = mailParser.getTo();

            return (mailToList.size() == 1) ? ((InternetAddress) mailToList.get(0)).getAddress().equals(MAIL_RECEIVER)
                    : false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test email "From" header.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailFrom() {
        try {
            String correctSubject = "CN=" + mailParser.getFrom();

            return correctSubject.equals(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test email "Date" header.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailDate() {
        try {
            Date sendDate = mailParser.getMimeMessage().getSentDate();
            long emailSendTimestamp = sendDate.getTime();
            long certNotBeforeTimestamp = certificate.getNotBefore().getTime();

            return (emailSendTimestamp == certNotBeforeTimestamp);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test email "ContentType" header.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailContentType() {
        try {
            return mailParser.getMimeMessage().getContentType().startsWith(MAIL_CONTENTTYPE);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test CSR email body.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testCSRFormat() {
        try {
            String csrBody = mailParser.getPlainContent().trim();

            if (!csrBody.startsWith(MAIL_BODYPREFIX))
                return false;
            else if (!csrBody.endsWith(MAIL_BODYPOSTFIX))
                return false;
            else {
                PemReader csrReader = new PemReader(new StringReader(csrBody));

                csr = new PKCS10CertificationRequest(csrReader.readPemObject().getContent());
                csrReader.close();

                ContentVerifierProvider prov = new JcaContentVerifierProviderBuilder()
                        .build(certificate.getPublicKey());

                return csr.isSignatureValid(prov);
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test CSR subject with certificate subject.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testCSRSubject() {
        try {
            String csrSubj = csr.getSubject().toString();
            String certSubj = certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);

            return csrSubj.equals(certSubj);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test CSR public key with certificate public key.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testCSRPubkey() {
        try {
            byte[] certPubkey = certificate.getPublicKey().getEncoded();
            byte[] csrPubkey = csr.getSubjectPublicKeyInfo().getEncoded();

            return Arrays.equals(certPubkey, csrPubkey);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test email body.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testMailBody() {
        if (!_testCSRFormat())
            return false;
        else if (!_testCSRSubject())
            return false;
        else if (!_testCSRPubkey())
            return false;
        else
            return true;
    }

    /**
     * Test mail DKIM signature with PSES.
     * 
     * @return return true if pass the testing.
     */
    private boolean _testDKIM() {
        try {
            boolean isDKIMPass = false;
            boolean isRetrieveDone = false;

            while (!isDKIMPass && !isRetrieveDone) {
                ByteArrayInputStream mailMsgStream = null;
                PSESDKIMKeyRetriever dkimKeyRetriever = null;
                DKIMVerifier verifier = null;

                try {
                    mailMsgStream = new ByteArrayInputStream(mailMsg);
                    dkimKeyRetriever = new PSESDKIMKeyRetriever(psesData, mailParser.getMimeMessage().getSentDate());
                    verifier = new DKIMVerifier(dkimKeyRetriever);

                    List<SignatureRecord> records = verifier.verify(mailMsgStream);

                    if (records != null && records.size() > 0)
                        isDKIMPass = true;

                } catch (FailException e) {
                } finally {
                    if (dkimKeyRetriever != null)
                        isRetrieveDone = dkimKeyRetriever.isRetrieveDone();
                }
            }

            return isDKIMPass;
        } catch (Exception e) {
            return false;
        }
    }
}