package show.proof.pcca.verifier.lib;

/**
 * Provides the report data for verification.
 *
 */
public class PCCAVerifierReport {
    /**
     * the error code of verification result.
     */
    public PCCAErrors retCode = PCCAErrors.UNKNOW;

    /**
     * the certificate subject
     */
    public String certSubject = "";
    /**
     * the certificate key hash
     */
    public String certKeyHash = "";
    /**
     * the not before date string of certificate
     */
    public String certNotBefore = "";
    /**
     * the not after date string of certificate
     */
    public String certNotAfter = "";
}