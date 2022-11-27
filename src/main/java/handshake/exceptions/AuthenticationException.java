package handshake.exceptions;

public class AuthenticationException extends Exception {

    public AuthenticationException() {
    }

    public AuthenticationException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
