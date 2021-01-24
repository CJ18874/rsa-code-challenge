package rsa.challenge;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.StringUtils;

import com.codahale.shamir.Scheme;

/**
 * Private key is used to sign a mail / file by the sender and public key is
 * used to verify the signature of the mail / file by the recipient. Private key
 * contains the prime numbers, modulus, public exponent, private exponent and
 * coefficients. Public key contains modulus and public exponent. Modulus (n) is
 * the product of two prime numbers used to generate the key pair. Public
 * exponent (d) is the exponent used on signed / encoded data to decode the
 * original value.
 * 
 * @author cjy
 *
 */
@SpringBootApplication
public class RsaCodeChallengeApplication implements CommandLineRunner {

	private static final Logger logger = LoggerFactory.getLogger(RsaCodeChallengeApplication.class);
	public static String PUBLIC_KEY_FILE_NAME = "Public.TXT";
	public static String PRIVATE_KEY_FILE_NAME = "Shard[k].TXT";

	public static void main(String[] args) {
		SpringApplication.run(RsaCodeChallengeApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		logger.info("\n");

		KeyPair keyPair = generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		writePublicKey(publicKey);
		writePrivateKeyShards(privateKey, 5);
		reassemblesPrivateKeyShard(privateKey);
		
		String mySecret = "my secret ....";
		String encrypText = encryptText(publicKey,mySecret);		
		String decryptsText = decryptsCypherToPlainText(privateKey,encrypText);
		if(mySecret.equals(decryptsText)){
			logger.info("**** Message decrypted successfully ****");
		}
	}

	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		Provider kpgenProv = generator.getProvider();
		logger.info("**** Generating RSA key pair via " + kpgenProv.getInfo() + " ****");
		generator.initialize(2048, new SecureRandom());
		return generator.generateKeyPair();
	}

	public void writePublicKey(PublicKey publicKey) throws IOException {
		logger.info("**** Public key format " + publicKey.getFormat() + " ****");
		// Encoding the public key to save as text
		Base64.Encoder encoder = Base64.getEncoder();
		Writer out = new FileWriter(PUBLIC_KEY_FILE_NAME);
		logger.info("**** Write public key to " + PUBLIC_KEY_FILE_NAME + " ****");
		out.write("-----BEGIN PUBLIC KEY-----\n");
		out.write(encoder.encodeToString(publicKey.getEncoded()));
		out.write("\n-----END PUBLIC KEY-----\n");
		out.close();
	}

	/**
	 * Private Key broken into N shards
	 * 
	 * @param privateKey
	 * @param shards
	 * @throws IOException
	 */
	public void writePrivateKeyShards(PrivateKey privateKey, int n) throws IOException {
		logger.info("**** Private key format " + privateKey.getFormat() + " ****");
		
		// split an arbitrary secret S into N parts, of which at least K are required to reconstruct S
		int k = 2;
		final Scheme scheme = new Scheme(new SecureRandom(), n, k);
		final byte[] secret = privateKey.getEncoded();
		final Map<Integer, byte[]> parts = scheme.split(secret);
		
		String newFileName = StringUtils.replace(PRIVATE_KEY_FILE_NAME, "k", String.valueOf(n));
		Writer out = new FileWriter(newFileName);
		logger.info("**** Write private key shards to " + newFileName + " ****");
		parts.forEach((chip, value) -> {
			try {
				out.write(Base64.getEncoder().encodeToString(value)+"\n");
			} catch (IOException e) {
				logger.error(e.getMessage());
			}
		});
		out.close();
	}
	
	public String encryptText(PublicKey publicKey, String text) throws Exception {
		logger.info("**** Encrypt text ****");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	/**
	 * Reassembles the Private Key using shard 2 & 5.
	 * 
	 * @param privateKey
	 * @return
	 * @throws FileNotFoundException
	 */
	public byte[] reassemblesPrivateKeyShard(PrivateKey privateKey) throws FileNotFoundException {
		int n = 5, k = 2;
		
		String newFileName = StringUtils.replace(PRIVATE_KEY_FILE_NAME, "k", String.valueOf(n));
		File privateKeyFile = new File(newFileName);
		if (privateKeyFile.exists()) {
			Scanner scanner = new Scanner(privateKeyFile);
			logger.info("**** Read from private key file ****");
			int chip = 1;
			Map<Integer, byte[]> parts = new HashMap<>();
			while (scanner.hasNextLine()) {
				parts.put(chip, scanner.nextLine().getBytes());
				chip++;
			}
			scanner.close();
			logger.info("**** Reassembles the Private Key using shard 2 & 5 ****");
			final Scheme scheme = new Scheme(new SecureRandom(), n, k);
			return scheme.join(parts);
		}
		return null;
	}
	
	/**
	 * Decrypts the cypher text back into the plain text using the reassembled Private Key
	 * 
	 * @param privateKey
	 * @param encrypText
	 * @return
	 * @throws Exception
	 */
	public String decryptsCypherToPlainText(PrivateKey privateKey,String encrypText) throws Exception {
	    logger.info("**** Decrypts using private key ****");
	    
	    byte[] bytes = Base64.getDecoder().decode(encrypText);
	    Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
	    return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
	}

} 