import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class generatedKeys {

	public static void main(String[] args) {
		try {
			generatedRSAKeyPair();
			generatedMACSharedKey();
			System.out.println("Successfully generated RSA key pair and MAC shared Key.");
		} catch (Exception e)  {
            System.out.println("Error while generating keys: " + e.toString());
        }
	}
	
	// Generated RSA key pair(public and private keys) and stored into separated text files
	private static void generatedRSAKeyPair() throws NoSuchAlgorithmException, IOException {
		// Creating a KeyPairGenerator object
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		
		// Initializing the KeyPairGenerator
		keyPairGen.initialize(2048);
		
		// Creating/Generating a RSA key pair
		KeyPair keyPair = keyPairGen.genKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		      
		// Save RSA public key into text file
		FileWriter fwPublic = new FileWriter("rsaPublicKey.txt");
		PrintWriter pwPublic = new PrintWriter(fwPublic);
		String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		pwPublic.print(publicKeyString);
		pwPublic.close();
      
		// Save RSA private key into text file
		FileWriter fwPrivate = new FileWriter("rsaPrivateKey.txt");
		PrintWriter pwPrivate = new PrintWriter(fwPrivate);
		String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		pwPrivate.print(privateKeyString);
		pwPrivate.close();
	}
	
	// Generated a shared key for MAC and stored into a text file
	private static void generatedMACSharedKey() throws NoSuchAlgorithmException, IOException {
		// Creating a KeyGenerator object
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");

		// Creating a SecureRandom object
		SecureRandom secRandom = new SecureRandom();

		// Initializing the KeyGenerator
		keyGen.init(secRandom);

		// Creating/Generating a key
		SecretKey secretKey = keyGen.generateKey();	
		
		// Save MAC key into file
		FileWriter fileWriter = new FileWriter("macSharedKey.txt");
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.print(Base64.getEncoder().encodeToString(secretKey.getEncoded()));      
		printWriter.close();
	}
}
