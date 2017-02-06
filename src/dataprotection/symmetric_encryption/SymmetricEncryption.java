package dataprotection.symmetric_encryption;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.NoSuchPaddingException;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


public class SymmetricEncryption {

	final int AES_BLOCK_SIZE = 16;
	final String ALGORITHM = "AES";
	final String MODE_OF_OPERATION = "AES/ECB/NoPadding";

	Cipher aesEnc, aesDec;
	SecretKeySpec key;

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public SymmetricEncryption (byte[] byteKey) throws InvalidKeyException {
		
		try {
			key = new SecretKeySpec(byteKey, ALGORITHM);

			// Initializes the Encryption
   			aesEnc = Cipher.getInstance(MODE_OF_OPERATION);
    		aesEnc.init(Cipher.ENCRYPT_MODE, key);
		
			// Initializes the Decryption
   			aesDec = Cipher.getInstance(MODE_OF_OPERATION);
    		aesDec.init(Cipher.DECRYPT_MODE, key);
		
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);

		} catch (NoSuchPaddingException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}

    /*************************************************************************************/
	/* Method to encrypt 1 block of plaintext using AES */
    /*************************************************************************************/
	public byte[] encryptBlock(byte[] input) throws IllegalBlockSizeException, BadPaddingException {

		return aesEnc.doFinal(input);
	}

    /*************************************************************************************/
	/* Method to decrypt 1 block of plaintext using AES */
    /*************************************************************************************/
	public byte[] decryptBlock(byte[] input) throws IllegalBlockSizeException, BadPaddingException {

		return aesDec.doFinal(input);
	}
}
