package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // receive Bob's RSA public key
                final byte[] bobPubKeyEncoded = receive("bob");
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bobPubKeyEncoded);
                final PublicKey bobPK = KeyFactory.getInstance("RSA").generatePublic(keySpec);
                print("Received Bob's RSA public key: %s", hex(bobPubKeyEncoded));

                // generate fresh AES shared secret
                final KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128); // 128-bit AES key
                final SecretKey aesKey = kg.generateKey();
                final byte[] sharedSecret = aesKey.getEncoded();
                print("My shared secret (AES key): %s", hex(sharedSecret));

                // encrypt AES with Bob's RSA public key
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.ENCRYPT_MODE, bobPK);
                final byte[] encSharedSecret = rsa.doFinal(sharedSecret);

                // send encrypted AES to Bob
                send("bob", encSharedSecret);
                print("Sent encrypted AES key to Bob: %s", hex(encSharedSecret));

                // use AES/GCM with this key to encrypt message
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ct = aes.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                // send ct and iv to Bob
                send("bob", iv);
                send("bob", ct);

                print("Sent IV: %s", hex(iv));
                print("Sent ct: %s", hex(ct));
                print("I'm done");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // generate rsa key pair
                final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                final KeyPair keyPair = keyPairGenerator.generateKeyPair();

                // send RSA public key to Alice
                final byte[] bobPubEncoded = keyPair.getPublic().getEncoded();
                send("alice", bobPubEncoded);
                print("My RSA public key: %s", hex(bobPubEncoded));

                // receive encrypted AES key from Alice
                final byte[] encSharedSecret = receive("alice");
                print("Received encrypted AES key: %s", hex(encSharedSecret));

                // decrypt AES key with RSA private key
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                final byte[] sharedSecret = rsa.doFinal(encSharedSecret);
                print("Recovered shared secret (AES key): %s", hex(sharedSecret));

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                // receive iv and ct from Alice
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                print("Received IV: %s", hex(iv));
                print("Received ct: %s", hex(ct));

                // decrypt message using AES/GCM
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}