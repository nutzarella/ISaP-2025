package isp.signatures;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class SignatureExampleRSAPSS {
    public static void main(String[] args) throws Exception {
        final String document = "We would like to sign this.";

        final KeyPair key = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(key.getPrivate());
        signer.update(document.getBytes(StandardCharsets.UTF_8));
        final byte[] signature = signer.sign();

        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        verifier.initVerify(key.getPublic());
        verifier.update(document.getBytes(StandardCharsets.UTF_8));

        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}
