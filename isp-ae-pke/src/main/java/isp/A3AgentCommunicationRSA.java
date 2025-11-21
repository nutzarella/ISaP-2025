package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */

                final String msgA = "Super secret message to Bob";
                final byte[] pt = msgA.getBytes(StandardCharsets.UTF_8);

                // encrypt with B's pk
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = cipher.doFinal(pt);

                // send ct to B
                send("bob", ct);
                System.out.println("[A] Sent encrypted message to B.");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final byte[] ct = receive("alice");

                // decrypt with B's priv.k
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] pt = cipher.doFinal(ct);
                final String msg = new String(pt, StandardCharsets.UTF_8);

                System.out.printf("[B] Decrypted message: %s%n", msg);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
