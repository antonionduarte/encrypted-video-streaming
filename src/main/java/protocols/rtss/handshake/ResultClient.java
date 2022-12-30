package protocols.rtss.handshake;

import config.CipherConfig;

import java.net.InetSocketAddress;

public record ResultClient(InetSocketAddress clientAddress, CipherConfig cipherConfig) {
}
