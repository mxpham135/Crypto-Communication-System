import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class receiver {

	public static void main(String[] args) {
		try {
			// Read the transmitted data file 
			String input = readFile("transmitted-data.txt");
			
			// split the encrypted input 
			String[] encryptedInput = input.split("\\s+");
			String encryptedPlainText = encryptedInput[0];
			String encryptedAESKey = encryptedInput[1];
			String encryptedMAC = encryptedInput[2];
			
			 // Read in MAC shared key 
	        String macSecretKey = readFile("macSharedKey.txt");
	        
			// Encrypt everything with MAC secret key
	        String encryptedPlainTextandAESKey = encryptedPlainText + encryptedAESKey;
	        String macString = encryptMAC(encryptedPlainTextandAESKey, macSecretKey);
			
			// Authenticate the data
	        boolean result = macCompare(macString.getBytes(), encryptedMAC.getBytes());	   
	        
	        // If save, decrypt the AES key and plaintext
	        if (result) {
		        System.out.println("The Message is safe.");
		        // Get RSA Private Key
		        String PrivateKey = readFile("rsaPrivateKey.txt");
		        PrivateKey rsaPrivateKey = getPrivateKey(PrivateKey);
		        
		        // Decrypt the AES Key with RSA private key
		        String decryptedAESKey = decryptAESKey(encryptedAESKey, rsaPrivateKey);
		        
		        // Decrypt message using decrypted AES key
		        String decryptedPlainText = decryptAESMessage(encryptedPlainText, decryptedAESKey);
		        
		        System.out.println("The Message is = " + decryptedPlainText);
	        }
	        // else notify the data transmitted is unsafe
	        else
		        System.out.println("The Message is unsafe.");     

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// read key from input filename
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
	
	// get private key from input string 
    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec;
        KeyFactory keyFactory;
        
        try {
        	keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }
    
	// Decrypt AES Key using RSA private key, return a String
    private static String decryptAESKey(String encryptedAESKey, PrivateKey privateKey) {
        Cipher cipher;
        
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
		} catch (Exception e) {
			e.printStackTrace();
		} 
        return null;
    }
    
	// Decrypt message using AES key, return in a String
    public static String decryptAESMessage(String strToDecrypt, String aesKey) {
    	Cipher cipher;
    	SecretKeySpec secretKey = null;
    	
    	try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            secretKey = new SecretKeySpec(aesKey.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
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
    
    // Authenticate the message
	private static Boolean macCompare(byte[] message1, byte[] message2) {	
		for (int i = 0; i < message1.length; i ++) {
			if (message1[i] != message2[i]) {
				return false;
			}
		}
		return true;
	}
}
