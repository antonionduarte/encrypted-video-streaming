package handshake.exceptions;

public class NoCiphersuiteException extends Exception {

    public NoCiphersuiteException() {
    }

    public NoCiphersuiteException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
