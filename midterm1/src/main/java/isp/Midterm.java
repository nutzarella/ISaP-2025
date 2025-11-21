package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Midterm {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        final Environment env = new Environment();

        // alice knows pk, server knows both
        final KeyPair serverRSA = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // shared password between alice and server
        final String pwd = "4l7c3sup3rs3cr3tp4sw00rd123!";

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                // 1.
                // A gen kp
                final KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(256);
                final KeyPair aliceKP = g.generateKeyPair();
                send("server", aliceKP.getPublic().getEncoded());

                // receive B and S(sk, A || B)
                final byte[] sEncPK = receive("server");
                final byte[] sigDelta = receive("server");
                final byte[] ivB = receive("server");
                final byte[] challBytes = receive("server");

                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(serverRSA.getPublic());

                PublicKey sPK = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(sEncPK));
                final byte[] result = new byte[aliceKP.getPublic().getEncoded().length + sPK.getEncoded().length];
                for (int i = 0; i < aliceKP.getPublic().getEncoded().length; i++) {
                    result[i] = aliceKP.getPublic().getEncoded()[i];
                }
                for (int j = 0; j < result.length - aliceKP.getPublic().getEncoded().length; j++) {
                    result[aliceKP.getPublic().getEncoded().length + j] = sPK.getEncoded()[j];
                }

                verifier.update(result);

                if (!verifier.verify(sigDelta)) {
                    print("Could not authenticate signed m from server!");
                    return;
                }
                print("Auth successful!");

                KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(aliceKP.getPrivate());
                dh.doPhase(sPK, true);
                final byte[] sharedSecret = dh.generateSecret();

                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] aesKeyBytes = sha.digest(sharedSecret);
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, 0, 16, "AES");

                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcm = new GCMParameterSpec(128, ivB);
                aes.init(Cipher.DECRYPT_MODE, aesKey, gcm);
                byte[] pt = aes.doFinal(challBytes);
                print("challBytes: %s", hex(challBytes));

                byte[] restUH = new byte[pwd.getBytes().length + pt.length];
                System.arraycopy(pwd.getBytes(), 0, restUH, 0, pwd.getBytes().length);
                System.arraycopy(pt, 0, restUH, pwd.getBytes().length, pt.length);

                byte[] resp = sha.digest(restUH);
                Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                SecureRandom rnd = new SecureRandom();
                byte[] iv = new byte[12];
                rnd.nextBytes(iv);
                GCMParameterSpec gcmE = new GCMParameterSpec(128, iv);
                encrypt.init(Cipher.ENCRYPT_MODE, aesKey, gcm);
                byte[] ct = encrypt.doFinal(resp);

                send("server", iv);
                send("server", ct);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                // 2.
                // create own secret value
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair serverKP = kpg.generateKeyPair();

                // receive A's encoded PK
                byte[] aEncPK = receive("alice");
                PublicKey aPK = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(aEncPK));

                // combine secret value b with A pk --> obtain DH shared secret
                KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(serverKP.getPrivate()); // sets secret scalar b
                dh.doPhase(aPK, true); // feeds in other party's g^a
                final byte[] sharedSecretBytes = dh.generateSecret(); // computes shared DH secret

                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] aesKeyBytes = sha.digest(sharedSecretBytes);

                // turn it into a key
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes,  0, 16, "AES"); // take bytes 0-16 to use for aesKey only
                print("aesKey: %s", hex(aesKeyBytes));

                // A || B
                byte[] result = new byte[aPK.getEncoded().length + serverKP.getPublic().getEncoded().length];
                for (int i=0; i < aPK.getEncoded().length; i++) {
                    result[i] = aPK.getEncoded()[i];
                }
                for (int j=0; j < result.length - aPK.getEncoded().length; j++) {
                    result[aPK.getEncoded().length + j] = serverKP.getPublic().getEncoded()[j];
                }
                print(hex(result));

                // sign the result with SHA-256
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(serverRSA.getPrivate());
                signature.update(result);
                byte[] sig = signature.sign();

                send("alice", serverKP.getPublic().getEncoded()); // sent B
                send("alice", sig); // sent S(sk, A || B)

                // pick a random 256-bit (32-byte) value chall
                SecureRandom rnd = new SecureRandom();
                byte[] random256 = new byte[32];
                rnd.nextBytes(random256);

                byte[] iv = new byte[12];
                rnd.nextBytes(iv);

                // symmetrically encrypt it using k (AES/GCM)
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
                aes.init(Cipher.ENCRYPT_MODE, aesKey, gcm);
                byte[] ct = aes.doFinal(random256);
                print("challBytes: %s", hex(ct));
                // send encrypted value to Alice
                send("alice", iv);
                send("alice", ct);

                byte[] ivB = receive("alice");
                byte[] respHB = receive("alice");

                Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcm2 = new GCMParameterSpec(128, ivB);
                decrypt.init(Cipher.DECRYPT_MODE, aesKey, gcm2);
                byte[] pt = aes.doFinal(respHB);
            }
        });

        env.connect("alice", "server");
        env.start();
    }
}
