package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // simulate poorly chosen key
        byte[] poorlyChosenKey = new byte[8];
        // first 5 keep at 0, last 3 random
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[3];
        random.nextBytes(randomBytes);
        poorlyChosenKey[5] = randomBytes[0];
        poorlyChosenKey[6] = randomBytes[1];
        poorlyChosenKey[7] = randomBytes[2];

        // encrypt
        SecretKeySpec keySpec = new SecretKeySpec(poorlyChosenKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ct = cipher.doFinal(message.getBytes());

        System.out.println("[CT] " + Agent.hex(ct));

        // break it
        byte[] foundKey = bruteForceKey(ct, message);
        System.out.println("[KEY FOUND] " + Agent.hex(foundKey));
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        // we know key of form: [0, 0, 0, 0, 0, ?, ?, ?]
        byte[] key = new byte[8]; // first 5 bytes already 0

        // brute force last 3
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                for (int k = 0; k < 256; k++) {
                    key[5] = (byte) i;
                    key[6] = (byte) j;
                    key[7] = (byte) k;

                    // decrypt with current key
                    if (decryptWithGeneratedKey(key, ct, message)) {
                        return key;
                    }
                }
            }
        }
        return null; // key not found
    }

    private static boolean decryptWithGeneratedKey(byte[] key, byte[] ct, String expectedMessage) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decrypted = cipher.doFinal(ct);
            String decryptedMessage = new String(decrypted);

            // check if decrypted matches expected
            return decryptedMessage.equals(expectedMessage);
        } catch (Exception e) {
            return false; // decryption failed
        }
    }
}
