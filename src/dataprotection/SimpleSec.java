package dataprotection;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import java.io.Console;

import dataprotection.asymmetric_encryption.RSALibrary;
import dataprotection.symmetric_encryption.SymmetricCipher;

public class SimpleSec {

	private static RSALibrary rsa = new RSALibrary();;
	private static SymmetricCipher aesCipher = new SymmetricCipher();

	public static void main(String[] args) throws Exception {

		System.out.println("_________    _\n" + "||_______   |_|\n" + "||\n"
				+ "||                                _______                 ______\n"
				+ "||          ||  ||\\\\      //||  ||______||  ||          ||______\n"
				+ "||_______   ||  || \\\\    // ||  ||      ||  ||          ||\n"
				+ "________||  ||  ||  \\\\  //  ||  ||______||  ||          ||______\n"
				+ "        ||  ||  ||   \\\\//   ||  ||______||  ||          ||______\n"
				+ "        ||  ||  ||          ||  ||          ||          ||\n"
				+ "________||  ||  ||          ||  ||          ||________  ||______\n"
				+ "________||  ||  ||          ||  ||          ||________  ||______\n");

		System.out.println("_________\n" + "||_______\n" + "||\n" + "||            ______    _____\n"
				+ "||          ||______  ||_____\n" + "||_______   ||        ||\n" + "________||  ||______  ||\n"
				+ "        ||  ||______  ||\n" + "        ||  ||        ||\n" + "________||  ||______  ||_____\n"
				+ "________||  ||______  ||_____\n");

		if (args.length >= 1) {
			String command = args[0];
			String sourceFile = "";
			String destinationFile = "";

			if (command.equals("g")) {
				if (args.length == 1) {
					generateKeys();
				} else {
					System.err.println("Something wrong has occured, select a valid command.");
				}
			} else if (command.equals("e")) {
				if (args.length == 3) {
					sourceFile = args[1];
					destinationFile = args[2];
					encryptFile(sourceFile, destinationFile);
				} else {
					System.err.println("Something wrong has occured, select a valid command.");
				}
			} else if (command.equals("d")) {
				if (args.length == 3) {
					sourceFile = args[1];
					destinationFile = args[2];
					decryptFile(sourceFile, destinationFile);
				} else {
					System.err.println("Something wrong has occured, select a valid command.");
				}
			} else if (command.equals("h")) {
				if (args.length == 1) {
					System.out.println("Allowed commands:\n" + "	g -> Generate keys\n"
							+ "	e <source file> <destination file> -> Encrypt and sign a file\n"
							+ "	d <source file> <destination file> -> Decrypt and validate a file\n" + "	h -> Help");
				} else {
					System.err.println("Something wrong has occured, select a valid command.");
				}
			} else {
				System.err.println("Something wrong has occured, select a valid command.");
			}
		} else {
			System.out.println("Type \"h\" for help.");
		}
	}

	private static void generateKeys() throws Exception {
		Console console = System.console();

		rsa.generateKeys();

		// Read password
		String password = "";
		System.out.println("Write a 16 length password:");
		while (password.length() != 16) {
			char[] passwordChar = console.readPassword();
			password = String.valueOf(passwordChar);

			if (password.length() != 16) {
				System.err.println("Invalid password, write a 16 length password:");
			}
		}

		// Hash function
		MessageDigest passwordDigest = MessageDigest.getInstance("SHA-256");
		passwordDigest.update(password.getBytes());
		byte[] hashedPassword = passwordDigest.digest();
		File hashedPasswordFile = new File("password.hash");
		FileOutputStream fileOutputStreamHashedPassword = new FileOutputStream(hashedPasswordFile, false);
		fileOutputStreamHashedPassword.write(hashedPassword);
		fileOutputStreamHashedPassword.close();

		// Encryption of the private key
		byte[] byteKey = aesCipher.stringToByte(password);
		File privateKeyFile = new File("private.key");
		byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
		byte[] encryptedPassword = aesCipher.encryptCBC(privateKeyBytes, byteKey);
		File encryptedPasswordFile = new File("private.key");
		FileOutputStream fileOutputStreamPasswordFile = new FileOutputStream(encryptedPasswordFile, false);
		fileOutputStreamPasswordFile.write(encryptedPassword);
		fileOutputStreamPasswordFile.close();

		System.out.println("The keys \"public.key\" and \"private.key\" has been generated\n");
	}

	private static void encryptFile(String sourceFile, String destinationFile) throws Exception {
		Console console = System.console();
		KeyFactory keyFactory = KeyFactory.getInstance(rsa.ALGORITHM);

		// AES encryption with the generated random key
		File fileToEncrypt = new File(sourceFile);

		// Check if the file exists and it is not a directory
		if (fileToEncrypt.exists() && !fileToEncrypt.isDirectory()) {
			byte[] textFileToEncrypt = Files.readAllBytes(fileToEncrypt.toPath());
			byte[] sessionKey = randomSessionKey();
			byte[] encryptedFile = aesCipher.encryptCBC(textFileToEncrypt, sessionKey);

			// Encryption of the AES session key with the public key
			File publicKeyFile = new File("public.key");
			// Check if the file exists and it is not a directory
			if (publicKeyFile.exists() && !publicKeyFile.isDirectory()) {
				byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
				byte[] encryptedSessionKey = rsa.encrypt(sessionKey, publicKey);

				System.out.println("Write the password of the file: ");
				char[] password = console.readPassword();
				if (password.length != 16) {
					System.err.println("The password is incorrect");
				} else {
					String stringPassword = String.valueOf(password);

					// Hash function
					MessageDigest passwordDigest = MessageDigest.getInstance("SHA-256");
					passwordDigest.update(stringPassword.getBytes());
					byte[] hashedPassword = passwordDigest.digest();

					File hashedPasswordFile = new File("password.hash");
					// Check if the file exists and it is not a directory
					if (hashedPasswordFile.exists() && !hashedPasswordFile.isDirectory()) {
						byte[] hashPasswordBytes = Files.readAllBytes(hashedPasswordFile.toPath());

						if (!aesCipher.byteToString(hashPasswordBytes).equals(aesCipher.byteToString(hashedPassword))) {
							System.err.println("The password is incorrect");
						} else {

							File encryptedPrivateKeyFile = new File("private.key");
							// Check if the file exists and it is not a
							// directory
							if (encryptedPrivateKeyFile.exists() && !encryptedPrivateKeyFile.isDirectory()) {
								byte[] encryptedPrivateKey = Files.readAllBytes(encryptedPrivateKeyFile.toPath());
								byte[] privateKeyBytes = aesCipher.decryptCBC(encryptedPrivateKey,
										aesCipher.stringToByte(stringPassword));
								PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
								PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

								// Load the text file and sign it
								File plaintextFile = new File(sourceFile);
								byte[] plaintext = Files.readAllBytes(plaintextFile.toPath());
								byte[] signature = rsa.sign(plaintext, privateKey);

								// Store the encrypted message, the encrypted
								// key
								// and
								// the
								// signature in a text file
								File encryptedMessageFile = new File(destinationFile);
								encryptedMessageFile.createNewFile();
								FileOutputStream fileOutputStream = new FileOutputStream(encryptedMessageFile);
								fileOutputStream.write(encryptedFile);
								fileOutputStream.write(rsa.stringToByte("--__--"));
								fileOutputStream.write(encryptedSessionKey);
								fileOutputStream.write(rsa.stringToByte("--__--"));
								fileOutputStream.write(signature);
								fileOutputStream.close();

								System.out.println("The encrypted file \"" + destinationFile + "\" has been saved\n");
							} else {
								System.err.println("The \"private.key\" file does not exist!");
							}
						}
					} else {
						System.err.println("The \"pasword.hash\" file does not exist!");
					}
				}
			} else {
				System.err.println("The \"public.key\" file does not exist!");
			}
		} else {
			System.err.println("The selected source file does not exist!");
		}
	}

	private static void decryptFile(String sourceFile, String destinationFile) throws Exception {
		Console console = System.console();

		KeyFactory keyFactory = KeyFactory.getInstance(rsa.ALGORITHM);

		File encryptedFile = new File(sourceFile);

		// Check if the file exists and it is not a directory
		if (encryptedFile.exists() && !encryptedFile.isDirectory()) {
			byte[] encryptedFileBytes = Files.readAllBytes(encryptedFile.toPath());
			if (new String(encryptedFileBytes).contains("--__--")) {
			byte[][] fileParts = splitBytes(encryptedFileBytes, "--__--".getBytes());
			byte[] encryptedMessage = fileParts[0];
			byte[] encryptedSessionKey = fileParts[1];
			byte[] signature = fileParts[2];

			// Decrypt session key
			// Load and decrypt the private key
			System.out.println("Write the password of the file: ");
			char[] password = console.readPassword();
			if (password.length != 16) {
				System.err.println("The password is incorrect");
			} else {
				String stringPassword = String.valueOf(password);

				// Hash function
				MessageDigest passwordDigest = MessageDigest.getInstance("SHA-256");
				passwordDigest.update(stringPassword.getBytes());
				byte[] hashedPassword = passwordDigest.digest();

				File hashedPasswordFile = new File("password.hash");
				// Check if the file exists and it is not a directory
				if (hashedPasswordFile.exists() && !hashedPasswordFile.isDirectory()) {
					byte[] hashPasswordBytes = Files.readAllBytes(hashedPasswordFile.toPath());

					if (!aesCipher.byteToString(hashPasswordBytes).equals(aesCipher.byteToString(hashedPassword))) {
						System.err.println("The password is incorrect");
					} else {

						try {
							// Decrypt session key
							File encryptedPrivateKeyFile = new File("private.key");
							// Check if the file exists and it is not a
							// directory
							if (encryptedPrivateKeyFile.exists() && !encryptedPrivateKeyFile.isDirectory()) {
								byte[] encryptedPrivateKey = Files.readAllBytes(encryptedPrivateKeyFile.toPath());
								byte[] privateKeyBytes = aesCipher.decryptCBC(encryptedPrivateKey,
										aesCipher.stringToByte(stringPassword));
								PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
								PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
								byte[] decryptedSessionKey = rsa.decrypt(encryptedSessionKey, privateKey);

								// Decrypt text file
								byte[] decryptedTextFile = aesCipher.decryptCBC(encryptedMessage, decryptedSessionKey);

								// Signature validation
								// Load the public key
								File publicKeyFile = new File("public.key");
								// Check if the file exists and it is not a
								// directory
								if (publicKeyFile.exists() && !publicKeyFile.isDirectory()) {
									byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
									X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
									PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

									if (rsa.verify(decryptedTextFile, signature, publicKey)) {
										// Store the decrypted message in a text
										// file
										File decryptedMessageFile = new File(destinationFile);
										decryptedMessageFile.createNewFile();
										FileOutputStream fileOutputStream = new FileOutputStream(decryptedMessageFile);
										fileOutputStream.write(decryptedTextFile);
										fileOutputStream.close();

										System.out.println(
												"The signature has been successfully verified and the decrypted file \""
														+ destinationFile + "\" has been saved\n");
									} else {
										System.err.println("The signature was not successfully verified.");
									}
								} else {
									System.err.println("The \"public.key\" file does not exist!");
								}
							} else {
								System.err.println("The \"private.key\" file does not exist!");
							}
						} catch (IllegalArgumentException e) {
							System.err.println("Wrong key pair when decrypting!");
						}
					}
				} else {
					System.err.println("The \"pasword.hash\" file does not exist!");
				}
			}
			} else {
				System.err.println("The selected source file is not valid!");
			}
		} else {
			System.err.println("The selected source file does not exist!");
		}
	}

	private static byte[] randomSessionKey() {

		String sessionKey = "";

		// Generate session key with characters between 42 and 122 (included) in
		// ASCII
		for (int i = 0; i < 16; i++) {
			sessionKey = sessionKey + String.valueOf(Character.toChars((int) ((81 * Math.random()) + 42)));
		}

		return aesCipher.stringToByte(sessionKey);
	}

	private static byte[][] splitBytes(byte[] input, byte[] token) {

		byte[][] parts = new byte[3][];

		ArrayList<Integer> match = new ArrayList<Integer>();

		for (int i = 0; i < input.length - token.length; i++) {
			if ((input[i] == token[0]) && (input[i + 1] == token[1]) && (input[i + 2] == token[2])
					&& (input[i + 3] == token[3]) && (input[i + 4] == token[4]) && (input[i + 5] == token[5])) {
				match.add(i);
			}
		}
		byte[] first = new byte[match.get(0)];
		byte[] second = new byte[match.get(1) - (match.get(0) + token.length)];
		byte[] third = new byte[input.length - (match.get(1) + token.length)];

		System.arraycopy(input, 0, first, 0, first.length);
		System.arraycopy(input, match.get(0) + token.length, second, 0, second.length);
		System.arraycopy(input, match.get(1) + token.length, third, 0, third.length);

		parts[0] = first;
		parts[1] = second;
		parts[2] = third;

		return parts;
	}

}
