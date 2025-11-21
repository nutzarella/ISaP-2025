package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Implement an unauthenticated (as presented in the slides) key exchange between Alice and Bob
 * using public-key encryption. Once the shared secret is established, send an encrypted message
 * from Alice to Bob using AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

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
