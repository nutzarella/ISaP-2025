package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                for (int i = 0; i < 10; i++) {
                    // hmac
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(key);
                    byte[] hmac = mac.doFinal(pt);

                    send("bob", pt);
                    send("bob", hmac);

//                    System.out.println("A's pt [" + i + "]: " + Arrays.toString(pt));
//                    System.out.println("A's hmac [" + i + "]: " + Arrays.toString(hmac));

                    // receive reply from Bob
                    byte[] replyPlaintext = receive("bob");
                    byte[] replyHmac = receive("bob");

                    // verify Bob's hmac
                    Mac macVerify = Mac.getInstance("HmacSHA256");
                    macVerify.init(key);
                    byte[] computedHmac = macVerify.doFinal(replyPlaintext);

                    if (MessageDigest.isEqual(replyHmac, computedHmac)) {
                        System.out.println("Alice received verified reply: " +
                                new String(replyPlaintext, StandardCharsets.UTF_8));
                    } else {
                        System.out.println("Alice detected tampering in Bob's reply #" + i);
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String text = "I know.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                for (int i = 0; i < 10; i++) {
                    // receive
                    byte[] receivedPlaintext = receive("alice");
                    byte[] receivedHmac = receive("alice");

                    // recalc hmac
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(key);
                    byte[] computedHmac = mac.doFinal(receivedPlaintext);

                    // verify
                    if (MessageDigest.isEqual(receivedHmac, computedHmac)) {
                        System.out.println("Bob received verified message: " +
                                new String(receivedPlaintext, StandardCharsets.UTF_8));
                    } else {
                        System.out.println("Bob detected tampering in message #" + i);
                    }

                    // hmac for reply
                    Mac macReply = Mac.getInstance("HmacSHA256");
                    macReply.init(key);
                    byte[] replyHmac = macReply.doFinal(pt);

                    send("alice", pt);
                    send("alice", replyHmac);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
