package show.proof.pcca.verifier.lib;

/**
 * Provides the error codes for verification.
 *
 */
public enum PCCAErrors {
    SUCCESS,
    INVALID_CERT_FORMAT,
    INVALID_MAIL_SUBJECT,
    INVALID_MAIL_TO,
    INVALID_MAIL_FROM,
    INVALID_MAIL_DATE,
    INVALID_MAIL_CONTENTTYPE,
    INVALID_MAIL_BODY,
    INVALID_MAIL_DKIM,
    UNKNOW
}