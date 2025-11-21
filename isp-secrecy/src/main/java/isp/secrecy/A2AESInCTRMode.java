package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
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
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */

                for (int i = 0; i < 10; i++) {
                    // create cipher
                    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, key);

                    // encrypt
                    final byte[] ct = cipher.doFinal(message.getBytes());

                    // get iv
                    final byte[] iv = cipher.getIV();

                    // send ct, iv to B
                    send("bob", ct);
                    send("bob", iv);

                    // wait for B's reply
                    final byte[] bCt = receive("bob"); // reply to ct
                    final byte[] bIv = receive("bob"); // reply to iv

                    // decrypt reply
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(bIv));
                    final byte[] bMsg = cipher.doFinal(bCt);
                    System.out.println("Alice received: " + new String(bMsg));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */

                for (int i = 0; i < 10; i++) {
                    // receive
                    final byte[] aCt = receive("alice");
                    final byte[] aIv = receive("alice");

                    // create same cipher, decrypt mode
                    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(aIv));

                    // decrypt
                    final byte[] pt = cipher.doFinal(aCt);
                    System.out.println("Bob received: " + new String(pt));

                    // encrypt & reply
                    final String reply = "I know.";
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] replyCt = cipher.doFinal(reply.getBytes());
                    final byte[] replyIv = cipher.getIV();

                    send("alice", replyCt); // send ct
                    send("alice", replyIv); // send iv
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
