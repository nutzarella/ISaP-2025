package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        final Environment env = new Environment();

        // Create key pairs
        final KeyPair aliceKey;
        final KeyPair bobKey;

        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            aliceKey = kpg.generateKeyPair();
            bobKey = kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signature pair, verify the signature
                // repeat 10 times

                final Signature signer = Signature.getInstance("SHA256withECDSA");
                final Signature verifier = Signature.getInstance("SHA256withECDSA");

                for (int i = 1; i <= 10; i++) {
                    final String msg = "Hello Bob, message #" + i;

                    // sign
                    signer.initSign(aliceKey.getPrivate());
                    signer.update(msg.getBytes(StandardCharsets.UTF_8));
                    final byte[] sig = signer.sign();

                    print("Sending: \"%s\"", msg);
                    print("Signature: %s", hex(sig));

                    // send message + signature
                    send("bob", msg.getBytes(StandardCharsets.UTF_8));
                    send("bob", sig);

                    // receive and verify
                    final byte[] receivedMsgBytes = receive("bob");
                    final byte[] receivedSig = receive("bob");
                    final String receivedMsg = new String(receivedMsgBytes, StandardCharsets.UTF_8);

                    verifier.initVerify(bobKey.getPublic());
                    verifier.update(receivedMsgBytes);

                    if (verifier.verify(receivedSig)) {
                        print("Received valid message from Bob: \"%s\"", receivedMsg);
                    } else {
                        print("Got invalid signature from Bob!");
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Signature signer = Signature.getInstance("SHA256withECDSA");
                final Signature verifier = Signature.getInstance("SHA256withECDSA");

                for (int i = 1; i <= 10; i++) {
                    // receive and verify
                    final byte[] receivedMsgBytes = receive("alice");
                    final byte[] receivedSignature = receive("alice");

                    verifier.initVerify(aliceKey.getPublic());
                    verifier.update(receivedMsgBytes);

                    if (verifier.verify(receivedSignature)) {
                        final String receivedMsg = new String(receivedMsgBytes, StandardCharsets.UTF_8);
                        print("Received valid message from Alice: \"%s\"", receivedMsg);
                    } else {
                        print("Got invalid signature from Alice!");
                    }

                    // respond
                    final String msg = "Hello Alice, reply #" + i;

                    signer.initSign(bobKey.getPrivate());
                    signer.update(msg.getBytes(StandardCharsets.UTF_8));
                    final byte[] sig = signer.sign();

                    print("Sending: \"%s\"", msg);
                    print("Signature: %s", hex(sig));

                    send("alice", msg.getBytes(StandardCharsets.UTF_8));
                    send("alice", sig);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}