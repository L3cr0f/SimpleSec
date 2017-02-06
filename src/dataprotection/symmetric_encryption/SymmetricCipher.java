package dataprotection.symmetric_encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;

	// Initialization Vector (fixed)

	byte[] iv = new byte[] { (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54, (byte) 55, (byte) 56,
			(byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54 };

	/*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
	/*************************************************************************************/
	public byte[] encryptCBC(byte[] input, byte[] byteKey) throws Exception {

		// First-> Generate the plaintext with padding
		byte[] paddedInput = this.addPadding(input);

		byte[] encryptedtext = new byte[paddedInput.length];

		// XOR operation in 16th first fields
		int i = 0;
		while (i < 16) {
			encryptedtext[i] = (byte) (this.iv[i] ^ paddedInput[i]);
			i++;
		}

		// Second -> Generate the encrypted text
		SymmetricEncryption encription = new SymmetricEncryption(byteKey);

		// New array to copy the encrypted blocks
		byte[] auxCipherText = new byte[16];
		// Block encryption
		for (int n = 0; n < encryptedtext.length; n = n + 16) {

			auxCipherText = encription.encryptBlock(Arrays.copyOfRange(encryptedtext, n, n + 16));

			// Counter m for aux encrypted block
			int m = 0;

			// Copying the aux cipher text to the final encrypted text
			for (int j = n; j < n + 16; j++) {
				encryptedtext[j] = auxCipherText[m];
				m++;
			}
			
			if (i < paddedInput.length) {
				// XOR operation to the next blocks using the encrypted text
				int l = 0;
				while (l < 16) {
					encryptedtext[i] = (byte) (auxCipherText[l] ^ paddedInput[i]);
					i++;
					l++;
				}
			}
		}

		return encryptedtext;
	}

	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
	/*************************************************************************************/

	public byte[] decryptCBC(byte[] input, byte[] byteKey) throws Exception {

		byte[] finalPaddedPlainText = new byte[input.length];

		// First -> Generate the plaintext
		SymmetricEncryption encription = new SymmetricEncryption(byteKey);

		// New array to copy the encrypted blocks
		byte[] auxPlainText = new byte[16];
		int i = 0;

		// Block encryption
		for (int n = 0; n < input.length; n = n + 16) {

			auxPlainText = encription.decryptBlock(Arrays.copyOfRange(input, n, n + 16));

			if (i < 16) {
				// XOR operation to the first block using the IV
				while (i < 16) {
					auxPlainText[i] = (byte) (auxPlainText[i] ^ this.iv[i]);
					i++;
				}
			} else if (i < input.length) {
				// XOR operation to the next blocks using the encrypted text
				int l = 0;
				while (l < 16) {
					auxPlainText[l] = (byte) (auxPlainText[l] ^ input[i - 16]);
					i++;
					l++;
				}
			}

			// Counter m for aux encrypted block
			int m = 0;

			// Copying the aux cipher text to the final encrypted text
			for (int j = n; j < n + 16; j++) {
				finalPaddedPlainText[j] = auxPlainText[m];
				m++;
			}
		}

		// Second -> Eliminate the padding
		// Get the padded bytes
		int numberOfAddedBytes = finalPaddedPlainText[finalPaddedPlainText.length - 1];

		// Final plain text
		byte[] finalPlainText = new byte[finalPaddedPlainText.length - numberOfAddedBytes];
		for (int j = 0; j < finalPlainText.length; j++) {
			finalPlainText[j] = finalPaddedPlainText[j];
		}

		return finalPlainText;
	}

	private byte[] addPadding(byte[] input) {

		int numberOfBytesToAdd = 16 - (input.length % 16);
		if (numberOfBytesToAdd == 0) {
			numberOfBytesToAdd = 16;
		}

		// Copy the input to the padded input
		byte[] paddedInput = new byte[input.length + numberOfBytesToAdd];
		for (int i = 0; i < input.length; i++) {
			paddedInput[i] = input[i];
		}

		// Doing the padding
		for (int i = 0; i < numberOfBytesToAdd; i++) {

			switch (numberOfBytesToAdd) {
			case 1:
				paddedInput[input.length + i] = 0x01;
				break;
			case 2:
				paddedInput[input.length + i] = 0x02;
				break;
			case 3:
				paddedInput[input.length + i] = 0x03;
				break;
			case 4:
				paddedInput[input.length + i] = 0x04;
				break;
			case 5:
				paddedInput[input.length + i] = 0x05;
				break;
			case 6:
				paddedInput[input.length + i] = 0x06;
				break;
			case 7:
				paddedInput[input.length + i] = 0x07;
				break;
			case 8:
				paddedInput[input.length + i] = 0x08;
				break;
			case 9:
				paddedInput[input.length + i] = 0x09;
				break;
			case 10:
				paddedInput[input.length + i] = 0x0a;
				break;
			case 11:
				paddedInput[input.length + i] = 0x0b;
				break;
			case 12:
				paddedInput[input.length + i] = 0x0c;
				break;
			case 13:
				paddedInput[input.length + i] = 0x0d;
				break;
			case 14:
				paddedInput[input.length + i] = 0x0e;
				break;
			case 15:
				paddedInput[input.length + i] = 0x0f;
				break;
			case 16:
				paddedInput[input.length + i] = 0x10;
				break;
			}
		}

		return paddedInput;
	}
	
	public byte[] stringToByte(String input) {
		byte[] inputByte = input.getBytes();
		return inputByte;
	}

	public String byteToString (byte[] input) {
		String inputString = new String(input, StandardCharsets.UTF_8);
		return inputString;
	}
}
