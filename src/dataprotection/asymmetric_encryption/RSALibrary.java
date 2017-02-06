package dataprotection.asymmetric_encryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;

public class RSALibrary {

	// String to hold name of the encryption algorithm.
	public final String ALGORITHM = "RSA";

	// String to hold the name of the private key file.
	public final String PRIVATE_KEY_FILE = "./private.key";

	// String to hold name of the public key file.
	public final String PUBLIC_KEY_FILE = "./public.key";

	// Maximum block size to encrypt and decrypt
	public final int MAX_ENCRYPTION_BLOCK_SIZE = 117;
	public final int MAX_DECRYPTION_BLOCK_SIZE = 128;

	/***********************************************************************************/
	/*
	 * Generates an RSA key pair (a public and a private key) of 1024 bits
	 * length
	 */
	/*
	 * Stores the keys in the files defined by PUBLIC_KEY_FILE and
	 * PRIVATE_KEY_FILE
	 */
	/* Throws IOException */
	/***********************************************************************************/
	public void generateKeys() throws IOException {

		try {

			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);

			// Use KeyGen to generate a public and a private key
			KeyPair keys = keyGen.generateKeyPair();
			PublicKey publicKey = keys.getPublic();
			PrivateKey privateKey = keys.getPrivate();

			// Store the public key in the file public.key
			X509EncodedKeySpec X509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
			File publicKeyFile = new File("public.key");
			publicKeyFile.createNewFile();

			FileOutputStream fileOutputStreamPubKey = new FileOutputStream(publicKeyFile);
			fileOutputStreamPubKey.write(X509EncodedKeySpec.getEncoded());

			fileOutputStreamPubKey.close();

			// Store the private key in the file private.key
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
			File privateKeyFile = new File("private.key");
			publicKeyFile.createNewFile();

			FileOutputStream fileOutputStreamPrivKey = new FileOutputStream(privateKeyFile);
			fileOutputStreamPrivKey.write(pkcs8EncodedKeySpec.getEncoded());

			fileOutputStreamPrivKey.close();

		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}

	/***********************************************************************************/
	/* Encrypts a plaintext using an RSA public key. */
	/* Arguments: the plaintext and the RSA public key */
	/* Returns a byte array with the ciphertext */
	/***********************************************************************************/
	public byte[] encrypt(byte[] plaintext, PublicKey key) {

		byte[] ciphertext = null;

		try {
			// Gets an RSA cipher object
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// Initialize the cipher object and use it to encrypt the plaintext
			cipher.init(Cipher.ENCRYPT_MODE, key);

			int textDivisions = (int) Math.ceil((double) plaintext.length / MAX_ENCRYPTION_BLOCK_SIZE);
			ArrayList<ArrayList<Byte>> completePlainText = new ArrayList<ArrayList<Byte>>();

			// Dividing the plaintext in blocks of 117 bytes maximum.
			int k = 0;
			for (int i = 0; i < textDivisions; i++) {
				completePlainText.add(new ArrayList<Byte>());
				for (int j = 0; j < MAX_ENCRYPTION_BLOCK_SIZE; j++) {
					if (k < plaintext.length) {
						completePlainText.get(i).add(plaintext[k]);
						k++;
					}
				}
			}

			ArrayList<ArrayList<Byte>> completeCipherText = new ArrayList<ArrayList<Byte>>();

			for (int i = 0; i < completePlainText.size(); i++) {

				// Create an auxiliary array to convert Byte to byte and copying
				// the data
				byte[] auxPlainText = new byte[completePlainText.get(i).size()];
				for (int j = 0; j < auxPlainText.length; j++) {
					auxPlainText[j] = completePlainText.get(i).get(j).byteValue();
				}
				completeCipherText.add(new ArrayList<Byte>());

				// Create an auxiliary array to convert byte to Byte and copying
				// the encrypted data
				byte[] auxCipherText = cipher.doFinal(auxPlainText);
				for (int j = 0; j < auxCipherText.length; j++) {
					completeCipherText.get(i).add(Byte.valueOf(auxCipherText[j]));
				}
			}

			// Gathering the encrypted data in one arraylist
			ArrayList<Byte> auxFinalCipherText = new ArrayList<Byte>();
			for (int i = 0; i < completeCipherText.size(); i++) {
				for (int j = 0; j < completeCipherText.get(i).size(); j++) {
					auxFinalCipherText.add(completeCipherText.get(i).get(j));
				}
			}

			// Transform the arraylist to an array
			ciphertext = new byte[auxFinalCipherText.size()];
			for (int i = 0; i < ciphertext.length; i++) {
				ciphertext[i] = auxFinalCipherText.get(i);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ciphertext;
	}

	/***********************************************************************************/
	/* Decrypts a ciphertext using an RSA private key. */
	/* Arguments: the ciphertext and the RSA private key */
	/* Returns a byte array with the plaintext */
	/***********************************************************************************/
	public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

		byte[] plaintext = null;

		try {
			// Gets an RSA cipher object
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// Initialize the cipher object and use it to decrypt the ciphertext
			cipher.init(Cipher.DECRYPT_MODE, key);

			// Divide the ciphertext in blocks of 128 bytes

			int textDivisions = (int) Math.ceil((double) ciphertext.length / MAX_DECRYPTION_BLOCK_SIZE);
			byte[][] completeCipherText = new byte[textDivisions][MAX_DECRYPTION_BLOCK_SIZE];

			// Dividing the plaintext in blocks of 117 bytes maximum.
			int k = 0;
			for (int i = 0; i < textDivisions; i++) {
				for (int j = 0; j < MAX_DECRYPTION_BLOCK_SIZE; j++) {
					completeCipherText[i][j] = ciphertext[k];
					k++;
				}
			}
			
			ArrayList<ArrayList<Byte>> completePlainText = new ArrayList<ArrayList<Byte>>();

			for (int i = 0; i < completeCipherText.length; i++) {
				
				completePlainText.add(new ArrayList<Byte>());
				
				byte[] auxPlainText = cipher.doFinal(completeCipherText[i]);
				
				// Create an auxiliary array to convert byte to Byte and copying
				// the encrypted data
				for (int j = 0; j < auxPlainText.length; j++) {
					completePlainText.get(i).add(Byte.valueOf(auxPlainText[j]));
				}
			}

			// Gathering the encrypted data in one arraylist
			ArrayList<Byte> auxFinalPlainText = new ArrayList<Byte>();
			for (int i = 0; i < completePlainText.size(); i++) {
				for (int j = 0; j < completePlainText.get(i).size(); j++) {
					auxFinalPlainText.add(completePlainText.get(i).get(j));
				}
			}


			// Transform the arraylist to an array
			plaintext = new byte[auxFinalPlainText.size()];
			for (int i = 0; i < plaintext.length; i++) {
				plaintext[i] = auxFinalPlainText.get(i);
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return plaintext;
	}

	/***********************************************************************************/
	/* Signs a plaintext using an RSA private key. */
	/* Arguments: the plaintext and the RSA private key */
	/* Returns a byte array with the signature */
	/***********************************************************************************/
	public byte[] sign(byte[] plaintext, PrivateKey key) {

		byte[] signedInfo = null;

		try {

			// Gets a Signature object
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature oject with the private key
			signature.initSign(key);


			// Set plaintext as the bytes to be signed
			signature.update(plaintext);

			// Sign the plaintext and obtain the signature (signedInfo)
			signedInfo = signature.sign();
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return signedInfo;
	}

	/***********************************************************************************/
	/* Verifies a signature over a plaintext */
	/*
	 * Arguments: the plaintext, the signature to be verified (signed) /* and
	 * the RSA public key
	 */
	/* Returns TRUE if the signature was verified, false if not */
	/***********************************************************************************/
	public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

		boolean result = false;

		try {

			// Gets a Signature object
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature oject with the public key
			signature.initVerify(key);

			// Set plaintext as the bytes to be veryfied
			signature.update(plaintext);

			// Verify the signature (signed). Store the outcome in the
			result = signature.verify(signed);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return result;
	}

	public byte[] stringToByte(String input) {
		byte[] inputByte = input.getBytes();
		return inputByte;
	}

	public String byteToString(byte[] input) {
		String inputString = new String(input, StandardCharsets.UTF_8);
		return inputString;
	}
}