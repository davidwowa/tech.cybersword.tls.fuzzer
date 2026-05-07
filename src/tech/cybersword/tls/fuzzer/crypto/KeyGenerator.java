package tech.cybersword.tls.fuzzer.crypto;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.util.LoggerUtil;

public class KeyGenerator {

	private static final Logger logger = LoggerUtil.getLogger(KeyGenerator.class.getName());

	// TODO
	public void generateKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			Key publicKey = kp.getPublic();
			Key privateKey = kp.getPrivate();
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "Could not generate RSA key pair", e);
		}
	}
}
