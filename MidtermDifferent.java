package isp.midterm1;

import java.security.KeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.KeySpec;

import fri.isp.Agent;
import fri.isp.Environment;

public class Midterm1 {
    public static void main(String[] args) throws Exception {
        Environment env = new Environment();

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair serverKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final String password = "lock123";

        env.add(new Agent("alice") {
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                final Signature aliceSigner = Signature.getInstance("SHA256withRSA");
                aliceSigner.initSign(aliceKP.getPrivate());
                aliceSigner.update(keyPair.getPublic().getEncoded());
                send("server", keyPair.getPublic().getEncoded());
                send("server", aliceSigner.sign());
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("server"));
                final ECPublicKey serverPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(serverPK, true);

                final byte[] sharedSecret = dh.generateSecret();
                final Key aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                aliceSigner.initVerify(serverKP.getPublic());
                aliceSigner.update(serverPK.getEncoded());
                if (aliceSigner.verify(receive("server"))) {
                    print("Valid signature from server.");
                } else {
                    print("Invalid signature from server.");
                }

                final byte[] tokenPayload = new byte[32];
                new SecureRandom().nextBytes(tokenPayload);
                final byte[] token = hash(1000, tokenPayload);

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                send("server", aes.doFinal(token));
                send("server", aes.getIV());

                send("lock", hash(999, tokenPayload));

            }
        });
        env.add(new Agent("server") {
            public void task() throws Exception {
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final ECParameterSpec dhParamSpec = alicePK.getParams();

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                final byte[] sharedSecret = dh.generateSecret();
                final Key aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Signature serverSigner = Signature.getInstance("SHA256withRSA");
                serverSigner.initVerify(aliceKP.getPublic());
                serverSigner.update(alicePK.getEncoded());
                if (serverSigner.verify(receive("alice"))) {
                    print("Valid signature from alice.");
                } else {
                    print("Invalid signature from alice.");
                }

                serverSigner.initSign(serverKP.getPrivate());
                serverSigner.update(keyPair.getPublic().getEncoded());
                send("alice", serverSigner.sign());

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] tokenCT = receive("alice");
                final byte[] tokenIV = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, tokenIV));
                final byte[] token = aes.doFinal(tokenCT);
                final byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                final byte[] tag = mac(token, password, salt);
                send("lock", token);
                send("lock", tag);
                send("lock", salt);

            }
        });
        env.add(new Agent("lock") {
            public void task() throws Exception {
                final byte[] token = receive("server");
                final byte[] receivedTag = receive("server");
                final byte[] salt = receive("server");
                byte[] verifiedToken = null;

                if (verify(token, receivedTag, password, salt)) {
                    verifiedToken = token;
                } else {
                    print("Verification failed.");
                }

                final byte[] receivedToken = receive("alice");

                if (MessageDigest.isEqual(verifiedToken, hash(1, receivedToken))) {
                    print("SUCCESS");
                    verifiedToken = receivedToken;
                } else {
                    print("FAILURE");
                }
            }
        });

        env.connect("alice", "server");
        env.connect("alice", "lock");
        env.connect("server", "lock");
        env.start();
    }

    /**
     * Hashes the given payload multiple times.
     * 
     * @param times
     * @param payload
     * @return the final hash value
     * @throws NoSuchAlgorithmException
     */
    public static byte[] hash(int times, byte[] payload) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] result = payload;
        for (int i = 1; i <= times; i++) {
            result = digest.digest(result);
        }
        return result;
    }

    /**
     * Computes the MAC tag over the message
     * 
     * @param payload  the message
     * @param password the password from which
     * @param salt     the salt useed to strengthen
     * @return the computed tag
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    public static byte[] mac(byte[] payload, String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt,
                1000, 128);
        final SecretKey generatedKey = pbkdf.generateSecret(specs);
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(generatedKey);
        return hmac.doFinal(payload);
    }

    /**
     * Verifies the MAC tag
     * 
     * @param payload
     * @param tag
     * @param password
     * @param salt
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verify(byte[] payload, byte[] tag, String password, byte[] salt)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        return MessageDigest.isEqual(mac(payload, password, salt), tag);
    }
}