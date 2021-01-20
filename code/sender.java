import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
public class sender {
	public static void main(String[] args) {
		try {
			// Message to be encrypted
	    	String plainText = readFile("message.txt");
	    	
	    	// get AES Key to encrypt message
	    	String aesKey = getAESKey();

	        // Encrypt message using AES key
	        String encryptedPlainText = encryptAESMessage(plainText, aesKey);

	        // Get RSA Public Key
	        String PublicKey = readFile("rsaPublicKey.txt");
	        PublicKey rsaPublicKey = getPublicKey(PublicKey);
	        
	        // Encrypt AES Key with RSA public Key
	        String encryptedAESKey = encryptAESKey(aesKey, rsaPublicKey);

	        // Read in MAC shared key 
	        String macSecretKey = readFile("macSharedKey.txt");
	        
	        // Encrypt everything with MAC secret key
	        String encryptedPlainTextandAESKey = encryptedPlainText + encryptedAESKey;
	        String encryptedMAC = encryptMAC(encryptedPlainTextandAESKey, macSecretKey);
	        
	        // Ready to transmit(saved) over to receiver
	        FileWriter fileWriter = new FileWriter("transmitted-data.txt");
	        PrintWriter printWriter = new PrintWriter(fileWriter);
	        printWriter.print(encryptedPlainText + "\n" + encryptedAESKey + "\n" + encryptedMAC);
	        printWriter.close();
	        
	        System.out.println("Data have been successfully transmitted(save).");

		} catch (IOException e) {
			e.printStackTrace();
		}
    }
	
    // Create an AES key with 128 bit
    private static String getAESKey() {
        KeyGenerator keyGen;
        SecretKey secretKey = null;
		
        try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
    
    // Encrypt message using AES key, return in a String
    public static String encryptAESMessage(String strToEncrypt, String aesKey) {
    	Cipher cipher;
    	SecretKeySpec secretKey = null;
    	
    	try{
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            secretKey = new SecretKeySpec(aesKey.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
        } catch (Exception e)  {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    
    // Read  key from input filename
    private static String readFile(String filename) {
        Path fileName = Path.of(filename);         
        String readString = null;
        
		try {
			readString = Files.readString(fileName);
		} catch (IOException e) {
			e.printStackTrace();
		}
        return readString;
    }
    
    // Generate RSA public key from input string 
    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        X509EncodedKeySpec keySpec;
        KeyFactory keyFactory;
        
        try{
            keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        } 
        return publicKey;
    }
    
    // Encrypt AES Key using RSA public key, return a String
    private static String encryptAESKey(String aesKey, PublicKey publicKey) {
        Cipher cipher;
        
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		    return Base64.getEncoder().encodeToString(cipher.doFinal(aesKey.getBytes()));
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
    }

    // Encrypt message with MAC shared key
    private static String encryptMAC(String message, String macSharedKey) {
    	Mac encryptMac;
    	SecretKeySpec secretKey = null;
    	
 	   	try {
 	   		secretKey = new SecretKeySpec(Base64.getDecoder().decode(macSharedKey.getBytes()), "HmacSHA256");
 	   		encryptMac = Mac.getInstance("HmacSHA256");
 	   		encryptMac.init(secretKey); 
 	   		return Base64.getEncoder().encodeToString(encryptMac.doFinal(message.getBytes())); 	   	
 	   	} catch ( Exception e) {
 		   e.printStackTrace();
 	   	}
 	   	return null;
    }
}