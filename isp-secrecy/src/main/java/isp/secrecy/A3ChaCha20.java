package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */

                for (int i = 0; i < 10; i++) {
                    // create cipher
                    final Cipher cipher = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(nonce);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));

                    // encrypt
                    final byte[] ct = cipher.doFinal(message.getBytes());

                    // send ct & nonce
                    send("bob", ct);
                    send("bob", nonce);

                    // receive ct & nonce
                    final byte[] bCt = receive("bob");
                    final byte[] bNonce = receive("bob");

                    // decrypt with B's nonce
                    cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(bNonce, 0));
                    final byte[] bMsg = cipher.doFinal(bCt);
                    System.out.println("Alice received: " + new String(bMsg));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO

                for (int i = 0; i < 10; i++) {
                    // receive
                    final byte[] aCt = receive("alice");
                    final byte[] aNonce = receive("alice");

                    // decrypt with A's nonce
                    final Cipher cipher = Cipher.getInstance("ChaCha20");
                    cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(aNonce, 0));
                    final byte[] pt = cipher.doFinal(aCt);
                    System.out.println("Bob received: " + new String(pt));

                    // encrypt
                    final String reply = "I know.";
                    final byte[] newNonce = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(newNonce);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(newNonce, 0));
                    final byte[] ct = cipher.doFinal(reply.getBytes());

                    // send ct & nonce
                    send("alice", ct);
                    send("alice", newNonce);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
