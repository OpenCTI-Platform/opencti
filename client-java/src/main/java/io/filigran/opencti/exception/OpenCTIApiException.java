package io.filigran.opencti.exception;

/**
 * Exception thrown when an error occurs during OpenCTI API operations.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
public class OpenCTIApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new OpenCTI API exception with the specified detail message.
     *
     * @param message the detail message
     */
    public OpenCTIApiException(String message) {
        super(message);
    }

    /**
     * Constructs a new OpenCTI API exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public OpenCTIApiException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new OpenCTI API exception with the specified cause.
     *
     * @param cause the cause of this exception
     */
    public OpenCTIApiException(Throwable cause) {
        super(cause);
    }
}

