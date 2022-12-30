package protocols.rtss.handshake;

import config.CipherConfig;

import java.net.InetSocketAddress;

public record ResultServer(String movieName, InetSocketAddress clientAddress, CipherConfig cipherConfig) {}
