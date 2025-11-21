package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        final Environment env = new Environment();

        // Create key pairs

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}