package handshake;

import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;

import java.io.IOException;
import java.net.*;

public class TLSHandshake implements Handshake {

    private byte[] secret;
    private final InetSocketAddress selfAddress;

    public TLSHandshake(InetSocketAddress selfAddress) {
        this.selfAddress = selfAddress;
    }

    @Override
    public void start(InetSocketAddress targetAddress) throws AuthenticationException {
        try (var clientSocket = new Socket(selfAddress.getAddress().getHostAddress(), selfAddress.getPort())) {
            clientSocket.connect(targetAddress);
            byte[] msg1 = generateFirstMessage();
            clientSocket.getOutputStream().write(msg1);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }



    @Override
    public InetSocketAddress waitClient() throws AuthenticationException, NoCiphersuiteException {
        try (var serverSocket = new ServerSocket(selfAddress.getPort())) {
            var clientSocket = serverSocket.accept();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public byte[] getSecret() {
        return secret;
    }

    private void waitServer() throws AuthenticationException {

    }

    private byte[] generateFirstMessage() {
        return null; //TODO
    }
}
