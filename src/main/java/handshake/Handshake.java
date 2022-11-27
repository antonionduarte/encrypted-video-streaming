package handshake;

import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

public interface Handshake {

    void start(InetSocketAddress serverAddress) throws AuthenticationException;

    InetSocketAddress waitClient() throws AuthenticationException, NoCiphersuiteException;

    byte[] getSecret();

}
