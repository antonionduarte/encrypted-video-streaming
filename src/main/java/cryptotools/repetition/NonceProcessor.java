package cryptotools.repetition;

import cryptotools.repetition.exceptions.RepeatedMessageException;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

public class NonceProcessor {

	private static NonceProcessor instance;
	private final SecureRandom random;

	private final Set<Integer> receivedNonces;

	private NonceProcessor() {
		this.receivedNonces = new HashSet<>();
		this.random = new SecureRandom();
	}

	public static NonceProcessor getInstance() {
		if (instance == null) {
			instance = new NonceProcessor();
		}
		return instance;
	}

	public void receiveNonce(int nonce) throws RepeatedMessageException {
		if (!receivedNonces.add(nonce)) {
			throw new RepeatedMessageException();
		}
	}

	public int generateNonce() {
		return random.nextInt();
	}
}
