package rsa.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.StringUtils;

@SpringBootTest
class RsaCodeChallengeApplicationTests {

	private static final Logger logger = LoggerFactory.getLogger(RsaCodeChallengeApplicationTests.class);
	@Autowired
	public RsaCodeChallengeApplication application;
	
	/**
	 * Creates the RSA key pair with a Private Key broken into 5 shards
	 */
	@Test
	public void testFirstScenario() {
		logger.info("** start testFirstScenario **");
		try {
			KeyPair keyPair = application.generateKeyPair();
			assertNotNull(keyPair, "Failed to create RSA key pair");

			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			application.writePublicKey(publicKey);
			assertTrue(new File(RsaCodeChallengeApplication.PUBLIC_KEY_FILE_NAME).exists(), "Failed to create a public key file");

			application.writePrivateKeyShards(privateKey, 5);
			assertTrue(new File(StringUtils.replace(RsaCodeChallengeApplication.PRIVATE_KEY_FILE_NAME, "k", String.valueOf(5))).exists(), "Failed to create a private key file");

		} catch (NoSuchAlgorithmException | IOException e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Encrypts a random plain text string using the RSA Public Key
	 */
	@Test
	public void testSecoundScenario() {
		logger.info("** start testSecoundScenario **");
		try {
			KeyPair keyPair = application.generateKeyPair();
			String expectedText = "rendom text ......";
			String actualText = application.encryptText(keyPair.getPublic(), expectedText);
			assertNotEquals(expectedText, actualText);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Reassembles the Private Key using shard 2 & 5
	 */
	@Test
	public void testThirdScenario() {
		try {
			KeyPair keyPair = application.generateKeyPair();
			byte[] shards = application.reassemblesPrivateKeyShard(keyPair.getPrivate());
			assertNotNull(shards);
		} catch (NoSuchAlgorithmException | FileNotFoundException e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Decrypts the cypher text back into the plain text using the reassembled Private Key.
	 * Asserts the decrypted plain text is equal to the original random plain text in Step 2.
	 */
	@Test
	public void testFourthAndFifthScenario() {
		try {
			KeyPair keyPair = application.generateKeyPair();
			String mySecret = "my secret ....";
			String encrypText = application.encryptText(keyPair.getPublic(), mySecret);
			String decryptsText = application.decryptsCypherToPlainText(keyPair.getPrivate(), encrypText);
			assertEquals(mySecret,decryptsText,"String are not the same");
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}
} 