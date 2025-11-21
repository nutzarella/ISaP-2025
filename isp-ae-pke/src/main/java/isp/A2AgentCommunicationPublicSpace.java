package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        // Create an AES key that is used by Bob and the public-space
        final SecretKey chachaKey = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                send("bob", data);

                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                final MessageDigest md = MessageDigest.getInstance("SHA-256");
                final byte[] digest = md.digest(data);


                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                final Cipher cipher = Cipher.getInstance("ChaCha20");
                final byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                cipher.init(Cipher.ENCRYPT_MODE, chachaKey, new ChaCha20ParameterSpec(nonce, 1));
                final byte[] ct = cipher.doFinal(digest);

                // Send nonce + ciphertext to Public Space
                send("public-space", nonce);
                send("public-space", ct);

                System.out.println("[Alice] Data and encrypted digest sent.");
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                final byte[] nonce = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher chachacipher = Cipher.getInstance("ChaCha20");
                chachacipher.init(Cipher.DECRYPT_MODE, chachaKey, new ChaCha20ParameterSpec(nonce, 1));
                final byte[] digest = chachacipher.doFinal(ct);

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher aescipher = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = new byte[12];
                new SecureRandom().nextBytes(iv);
                aescipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] digestCt = aescipher.doFinal(digest);

                send("bob", iv);
                send("bob", digestCt);
                System.out.println("[Public-Space] Forwarded encrypted digest to Bob.");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] data = receive("alice");
                final MessageDigest md = MessageDigest.getInstance("SHA-256");
                final byte[] localDigest = md.digest(data);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                final byte[] publicSpaceIv = receive("public-space");
                final byte[] publicSpaceCt = receive("public-space");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, publicSpaceIv));
                final byte[] receivedDigest = aes.doFinal(publicSpaceCt);

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                if (MessageDigest.isEqual(localDigest, receivedDigest)) {
                    System.out.println("[Bob] Data valid");
                } else {
                    System.out.println("[Bob] Data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
