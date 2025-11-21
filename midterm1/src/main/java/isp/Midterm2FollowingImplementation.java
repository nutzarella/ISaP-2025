package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * THE PROTOCOL  (copied from the instructions)
 *
 * In this assignment, you will implement a one-sided authenticated key-exchange protocol
 * between Alice and the server. This will be a slightly simplified variant of a
 * hand-shake protocol that occurs in TLSv1.3 which you use all the time when you browse the web.
 *
 * Client Alice will establish a connection over an insecure communication channel to the server.
 * Then she will run a one-sided authenticated key-exchange protocol in which a shared secret will
 * be created to secure subsequent communication.
 *
 * Initially, the protocol will only authenticate the server while Alice’s identity will remain
 * unconfirmed. To also authenticate Alice, the server will send a password challenge to which
 * Alice will have to correctly respond. When done so, her identity will be confirmed.
 *
 *
 * INITIAL SETTING  (copied from the instructions)
 *
 * Server is using an RSA public-secret key pair denoted as (pk, sk). Alice is assumed to know
 * the public key pk in advance.
 *
 * Alice does not have a keypair. Instead, she uses a password pwd. Similarly, this password is
 * also known to the server.
 *
 * In code, define the keypair and the password globally in the method main(String[] args) so
 * that Alice and Server can both access it. However, don’t access the secret key from within
 * the agent Alice: she may only use the public key pk and the password pwd. The server, however,
 * may also use the secret key sk.
 *
 *
 * DETAILED DESCRIPTION  (copied from the instructions)
 *
 * 1. Alice begins by initiating the Diffie-Hellman key-exchange protocol. Use the Elliptic Curve
 *    variant as we did in the labs; a good starting point for the assignment is the isp-keyagreement
 *    project.
 *
 *    Alice creates her secret value a and computes her public value A = g^a mod p. (While the notation
 *    might suggest the DH protocol is using the arithmetic modulo prime numbers, use the Elliptic
 *    curve variant.) She then sends the public value A to the server.
 *
 *    Implementation note. While the notation might suggest the DH protocol is using the arithmetic
 *    modulo prime numbers, use the Elliptic curve variant. In particular implement the key exchange
 *    with curve 25519. Few tips:
 *      - Use the appropriate algorithm name for generating key-pairs and running the key agreement;
 *      - Since the size of the keys in 25519 is standardized, there is no need to set their size
 *        (nor explicitly set their parameterSpec);
 *      - The class that holds the 25519 curve public key is called XECPublicKey;
 *      - If you decide not to use 25519 (and use EC instead, like we did in the labs) you will
 *        receive a deduction for this part of the assignment.
 *
 * 2. Similarly, server picks its own secret value b and computes its public value B = g^b mod p.
 *    It then receives Alice’s public value A, and combines it with its own secret value to obtain
 *    the Diffie-Hellman shared secret.
 *
 *    This value is then immediately hashed with SHA-256 and from the result an AES symmetric key
 *    is derived: k = H(A^b mod p). Since the hash will have 32 bytes, and the key requires only
 *    16 bytes, take the first 16 bytes as the key.
 *
 *    Next, the server concatenates Alice’s public value A and its own public value B and signs the
 *    result using RSA signing algorithm using SHA-256 and its secret key sk:
 *        σ = S(sk, A || B).
 *
 *    While the pair (B, σ) should be sufficient to prove to Alice that the server is genuine,
 *    the server cannot be sure whether Alice is really Alice – it might be someone impersonating her.
 *
 *    So the server issues a password-based challenge to Alice: the server will pick a random
 *    256-bit (32-byte) value chall, symmetrically encrypt it with the just derived symmetric key k
 *    using AES in GCM mode and send its encrypted value c_chall ← E(k, chall) to Alice, along with
 *    the DH public value B and the signature σ.
 *
 * 3. Alice receives the messages and immediately verifies the signature σ. If the signature fails,
 *    the protocol is aborted.
 *
 *    If the signature verifies, she computes the secret key k like the server:
 *        k = H(B^a mod p).
 *
 *    She then uses AES-GCM to decrypt the challenge:
 *        chall ← D(k, c_chall).
 *
 *    Next, she creates the response by appending the challenge chall to the password pwd and hashing
 *    the result with SHA-256:
 *        resp = H(pwd || chall).
 *
 *    Finally she encrypts the response
 *        c_resp ← E(k, resp)
 *    and sends the c_resp to the server. She is now done.
 *
 * 4. Server receives the ciphertext c_resp and decrypts it:
 *        resp' ← D(k, c_resp).
 *
 *    Finally, the server verifies the response: it hashes the concatenation of Alice’s password and
 *    the challenge value:
 *        expected = H(pwd || chall)
 *    and compares the result with the decrypted response resp'. If they match, Alice is authenticated.
 *    If not, the protocol is aborted.
 *
 *    If the protocol terminates successfully, both Alice and the server are authenticated and they
 *    share a secret key k which can be used to symmetrically encrypt and authenticate data.
 */
public class Midterm2FollowingImplementation {

    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        // --------------------------------------------------------------------
        // INITIAL SETTING (from the instructions)
        //
        // Server is using an RSA public-secret key pair denoted as (pk, sk).
        // Alice is assumed to know the public key pk in advance.
        //
        // Alice does not have a keypair. Instead, she uses a password pwd.
        // Similarly, this password is also known to the server.
        //
        // In code, define the keypair and the password globally in the method
        // main(String[] args) so that Alice and Server can both access it.
        // However, don’t access the secret key from within the agent Alice:
        // she may only use the public key pk and the password pwd. The server,
        // however, may also use the secret key sk.
        // --------------------------------------------------------------------
        final KeyPair serverRSA = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final String pwd = "4l7c3sup3rs3cr3tp4sw00rd123!";

        // ====================================================================
        // Alice
        // ====================================================================
        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                // ------------------------------------------------------------
                // 1. Alice begins by initiating the Diffie-Hellman key exchange
                //    protocol. We follow the implementation note and use
                //    curve 25519 with the correct algorithm name X25519.
                //
                //    Alice creates her secret value a and computes her public
                //    value A, then sends the public value A to the server.
                //
                //    Implementation note applied:
                //      - We use KeyPairGenerator.getInstance("X25519") and
                //        KeyAgreement.getInstance("X25519");
                //      - We do NOT set key size or params (25519 is fixed);
                //      - The public key object is an XECPublicKey internally.
                // ------------------------------------------------------------
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
                final KeyPair aliceKP = kpg.generateKeyPair();   // contains a (private) and A (public)

                // A = Alice's public key (encoded)
                final byte[] aEncoded = aliceKP.getPublic().getEncoded();
                send("server", aEncoded);

                // ------------------------------------------------------------
                // 3. Alice receives B, the signature σ = S(sk, A || B),
                //    and the encrypted challenge c_chall together with
                //    its IV for AES-GCM.
                // ------------------------------------------------------------
                final byte[] bEncoded = receive("server");   // B
                final byte[] sigma = receive("server");      // σ = S(sk, A || B)
                final byte[] ivChallenge = receive("server");// IV for c_chall
                final byte[] c_chall = receive("server");    // E(k, chall)

                // Rebuild server's X25519 public key B from the encoding
                final PublicKey serverDhPK =
                        KeyFactory.getInstance("X25519")
                                .generatePublic(new X509EncodedKeySpec(bEncoded));

                // ------------------------------------------------------------
                // 3. Alice immediately verifies the signature σ. The signature
                //    is over A || B using the server's public RSA key pk.
                //    If the signature fails, the protocol is aborted.
                // ------------------------------------------------------------
                final byte[] aConcatB = concat(aEncoded, bEncoded);

                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(serverRSA.getPublic());
                verifier.update(aConcatB);

                if (!verifier.verify(sigma)) {
                    print("Alice: signature verification FAILED. Aborting.");
                    return;
                }
                print("Alice: signature verification OK.");

                // ------------------------------------------------------------
                // 3. If the signature verifies, Alice computes the secret key k
                //    like the server:
                //        k = H(B^a mod p)
                //    which here is done using X25519 KeyAgreement followed by
                //    SHA-256 and taking the first 16 bytes.
                // ------------------------------------------------------------
                final KeyAgreement dh = KeyAgreement.getInstance("X25519");
                dh.init(aliceKP.getPrivate());          // uses secret scalar a
                dh.doPhase(serverDhPK, true);          // feeds in B
                final byte[] sharedSecret = dh.generateSecret();

                final MessageDigest shaForK = MessageDigest.getInstance("SHA-256");
                final byte[] kBytesFull = shaForK.digest(sharedSecret);
                final SecretKeySpec k = new SecretKeySpec(kBytesFull, 0, 16, "AES");

                // ------------------------------------------------------------
                // 3. She then uses AES-GCM to decrypt the challenge:
                //        chall ← D(k, c_chall).
                // ------------------------------------------------------------
                final Cipher aesDec = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec gcmCh = new GCMParameterSpec(128, ivChallenge);
                aesDec.init(Cipher.DECRYPT_MODE, k, gcmCh);
                final byte[] chall = aesDec.doFinal(c_chall);

                print("Alice: received and decrypted chall = %s", hex(chall));

                // ------------------------------------------------------------
                // 3. Next, she creates the response by appending the challenge
                //    chall to the password pwd and hashing the result with
                //    SHA-256:
                //        resp = H(pwd || chall).
                // ------------------------------------------------------------
                final byte[] pwdBytes = pwd.getBytes();
                final byte[] pwdConcatChall = concat(pwdBytes, chall);

                final MessageDigest shaForResp = MessageDigest.getInstance("SHA-256");
                final byte[] resp = shaForResp.digest(pwdConcatChall);

                // ------------------------------------------------------------
                // 3. Finally she encrypts the response
                //        c_resp ← E(k, resp)
                //    using AES-GCM and sends c_resp (together with its IV)
                //    to the server. She is now done.
                // ------------------------------------------------------------
                final Cipher aesEnc = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] ivResp = new byte[12];
                new SecureRandom().nextBytes(ivResp);
                final GCMParameterSpec gcmResp = new GCMParameterSpec(128, ivResp);
                aesEnc.init(Cipher.ENCRYPT_MODE, k, gcmResp);
                final byte[] c_resp = aesEnc.doFinal(resp);

                send("server", ivResp);
                send("server", c_resp);

                print("Alice: sent encrypted response to server.");
            }
        });

        // ====================================================================
        // Server
        // ====================================================================
        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {

                // ------------------------------------------------------------
                // 2. Server picks its own secret value b and computes its
                //    public value B using X25519. It then receives Alice's
                //    public value A and combines it with its own secret value
                //    to obtain the Diffie-Hellman shared secret.
                //
                //    Implementation note applied here as well: we use X25519
                //    and do not set key size or parameters explicitly.
                // ------------------------------------------------------------
                final byte[] aEncoded = receive("alice");  // A

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
                final KeyPair serverDhKP = kpg.generateKeyPair(); // contains b and B
                final byte[] bEncoded = serverDhKP.getPublic().getEncoded(); // B

                final PublicKey aPK =
                        KeyFactory.getInstance("X25519")
                                .generatePublic(new X509EncodedKeySpec(aEncoded));

                final KeyAgreement dh = KeyAgreement.getInstance("X25519");
                dh.init(serverDhKP.getPrivate());        // secret scalar b
                dh.doPhase(aPK, true);                   // feeds in A
                final byte[] sharedSecret = dh.generateSecret();

                // ------------------------------------------------------------
                // 2. This value is immediately hashed with SHA-256 and from
                //    the result an AES symmetric key is derived:
                //        k = H(A^b mod p).
                //    Since the hash has 32 bytes and the key requires only
                //    16 bytes, we take the first 16 bytes as the key.
                // ------------------------------------------------------------
                final MessageDigest shaForK = MessageDigest.getInstance("SHA-256");
                final byte[] kBytesFull = shaForK.digest(sharedSecret);
                final SecretKeySpec k = new SecretKeySpec(kBytesFull, 0, 16, "AES");

                // ------------------------------------------------------------
                // 2. Next, the server concatenates Alice’s public value A and
                //    its own public value B and signs the result using RSA with
                //    SHA-256 and its secret key sk:
                //        σ = S(sk, A || B).
                // ------------------------------------------------------------
                final byte[] aConcatB = concat(aEncoded, bEncoded);

                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(serverRSA.getPrivate());
                signer.update(aConcatB);
                final byte[] sigma = signer.sign();

                // ------------------------------------------------------------
                // 2. The server issues a password-based challenge to Alice.
                //    It picks a random 256-bit (32-byte) value chall,
                //    symmetrically encrypts it with k using AES-GCM and sends
                //    its encrypted value c_chall together with B and σ.
                // ------------------------------------------------------------
                final SecureRandom rnd = new SecureRandom();
                final byte[] chall = new byte[32];
                rnd.nextBytes(chall);

                final byte[] ivChallenge = new byte[12];
                rnd.nextBytes(ivChallenge);

                final Cipher aesEncChall = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec gcmCh = new GCMParameterSpec(128, ivChallenge);
                aesEncChall.init(Cipher.ENCRYPT_MODE, k, gcmCh);
                final byte[] c_chall = aesEncChall.doFinal(chall);

                // Send B, σ, IV for challenge and c_chall to Alice
                send("alice", bEncoded);
                send("alice", sigma);
                send("alice", ivChallenge);
                send("alice", c_chall);

                print("Server: sent B, signature and encrypted challenge.");

                // ------------------------------------------------------------
                // 4. Server receives the ciphertext c_resp from Alice, along
                //    with its IV, and decrypts it:
                //        resp' ← D(k, c_resp).
                // ------------------------------------------------------------
                final byte[] ivResp = receive("alice");
                final byte[] c_resp = receive("alice");

                final Cipher aesDecResp = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec gcmResp = new GCMParameterSpec(128, ivResp);
                aesDecResp.init(Cipher.DECRYPT_MODE, k, gcmResp);
                final byte[] respPrime = aesDecResp.doFinal(c_resp);

                // ------------------------------------------------------------
                // 4. The server verifies the response by computing
                //        expected = H(pwd || chall)
                //    and comparing it with resp'. If they match, Alice is
                //    authenticated; otherwise the protocol is aborted.
                // ------------------------------------------------------------
                final byte[] pwdBytes = pwd.getBytes();
                final byte[] pwdConcatChall = concat(pwdBytes, chall);

                final MessageDigest shaForExpected = MessageDigest.getInstance("SHA-256");
                final byte[] expected = shaForExpected.digest(pwdConcatChall);

                if (Arrays.equals(expected, respPrime)) {
                    print("Server: authentication SUCCESSFUL. Shared key k established.");
                } else {
                    print("Server: authentication FAILED. Aborting.");
                }
            }
        });

        env.connect("alice", "server");
        env.start();
    }

    // ------------------------------------------------------------------------
    // Helper: concatenate two byte arrays.
    // ------------------------------------------------------------------------
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // ------------------------------------------------------------------------
    // Helper: hex-encode byte array (used only for debug prints).
    // ------------------------------------------------------------------------
    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte d : data) {
            sb.append(String.format("%02x", d));
        }
        return sb.toString();
    }
}
