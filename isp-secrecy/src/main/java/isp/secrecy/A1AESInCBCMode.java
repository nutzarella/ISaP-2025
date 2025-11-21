package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
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
                    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, key);

                    // encrypt message
                    final byte[] ct = cipher.doFinal(message.getBytes());

                    // get init vector
                    final byte[] iv = cipher.getIV();

                    // send both to B
                    send("bob", ct);
                    send("bob", iv);

                    // wait for B's reply
                    final byte[] bobCt = receive("bob"); // reply to ct
                    final byte[] bobIv = receive("bob"); // reply to iv

                    // decrypt B's reply
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(bobIv));
                    final byte[] bobMessage = cipher.doFinal(bobCt);
                    System.out.println("Alice received: " + new String(bobMessage));
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
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

//                    System.out.println("B's received CT: " + new String(receivedCt));
//                    System.out.println("B's received IV: " + new String(receivedIv));

                    // create cipher which B knows as it's the same as A
                    // different mode -> DECRYPT
                    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(receivedIv));

                    // decrypt
                    final byte[] pt = cipher.doFinal(receivedCt);
                    System.out.println("Bob received: " + new String(pt));

                    // reply
                    final String reply = "I know."; // Han Solo reference, B's not a jerk :)
                    cipher.init(Cipher.ENCRYPT_MODE, key); // new iv
                    final byte[] replyCt = cipher.doFinal(reply.getBytes());
                    final byte[] replyIv = cipher.getIV();

                    send("alice", replyCt);
                    send("alice", replyIv);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
