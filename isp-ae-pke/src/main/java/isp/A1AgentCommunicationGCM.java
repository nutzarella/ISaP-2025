package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String baseMessage = "I hope you get this message intact and in secret. Kisses, Alice.";

                for (int i = 1; i <= 10; i++) {
                    final String message = baseMessage + " [#" + i + "]";
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    final byte[] iv = new byte[12];
                    new SecureRandom().nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] ct = cipher.doFinal(pt);

                    send("bob", ct);
                    send("bob", iv);
                    System.out.printf("[A] -> %s%n", message);

                    final byte[] replyCt = receive("bob");
                    final byte[] replyIv = receive("bob");

                    final Cipher decipher = Cipher.getInstance("AES/GCM/NoPadding");
                    decipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, replyIv));
                    final byte[] replyPt = decipher.doFinal(replyCt);
                    final String replyMsg = new String(replyPt, StandardCharsets.UTF_8);
                    System.out.printf("[A] <- %s%n", replyMsg);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 1; i <= 10; i++) {
                    final byte[] ct = receive("alice");
                    final byte[] iv = receive("alice");

                    final Cipher decipher = Cipher.getInstance("AES/GCM/NoPadding");
                    decipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] pt = decipher.doFinal(ct);
                    final String msg = new String(pt, StandardCharsets.UTF_8);
                    System.out.printf("[B] <- %s%n", msg);

                    final String reply = "Got your message #" + i + ". Regards, Bob.";
                    final byte[] replyPt = reply.getBytes(StandardCharsets.UTF_8);

                    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    final byte[] replyIv = new byte[12];
                    new SecureRandom().nextBytes(replyIv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, replyIv));
                    final byte[] replyCt = cipher.doFinal(replyPt);

                    send("alice", replyCt);
                    send("alice", replyIv);
                    System.out.printf("[B] -> %s%n", reply);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
