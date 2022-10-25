package com.oop;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class Main {

    final static String ciphertext = "ciphertext.enc";
    final static String ciphertext_mac1 = "0f4fe4423746dfe0c1956a7b65af33c1";
    final static String ciphertext_mac2 = "68d8aaef41c9c43ec483144cb8349800";

    public static void main(String[] args) throws Exception {

        Receiver receiver = new Receiver();

        // Extract the different parts of the data from the message
        byte[] key = receiver.extractBytes(ciphertext, 128, 0);
        byte[] IV = receiver.extractBytes(ciphertext, 128, 128);
        byte[] key_Hmac = receiver.extractBytes(ciphertext, 128, 256);
        byte[] message = receiver.extractBytes(ciphertext, 384);

        // Initialize RSA decoder
        PrivateKey privateKey = receiver.getPrivateKey();
        receiver.setDecoder("RSA");
        receiver.init_decoder(privateKey);

        // Decrypt RSA encoded Params
        key = receiver.decrypt(key);
        IV = receiver.decrypt(IV);
        key_Hmac = receiver.decrypt(key_Hmac);

        // Initialize AES decoder
        receiver.setDecoder("AES/CBC/PKCS5Padding");
        receiver.init_decoder(key, IV);

        // Decrypt AES encoded message
        byte[] msg = receiver.decrypt(message);
        String plaintext = new String(msg);

        // Generate the MAC
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec macKey = new SecretKeySpec(key_Hmac, "HmacMD5");
        mac.init(macKey);
        byte[] rawMac = mac.doFinal(msg);
        String macHexString = new BigInteger(1, rawMac).toString(16);

        if(macHexString.equals(ciphertext_mac1))
            System.out.println("ciphertext_mac1: Verified");
        else
            System.out.println("ciphertext_mac1: Verification failed");

        if(macHexString.equals(ciphertext_mac2))
            System.out.println("ciphertext_mac2: Verified");
        else
            System.out.println("ciphertext_mac2: Verification failed");

        // Read the public key from the file
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new FileInputStream("lab1Sign.cert"));
        PublicKey publicKey = certificate.getPublicKey();

        // Generate the signature object
        Signature signRSA = Signature.getInstance("sha1withRSA");
        signRSA.initVerify(publicKey);
        signRSA.update(msg);

        // Get provided signatures from the files
        byte[] signature1 = receiver.getSignature("ciphertext.enc.sig1");
        byte[] signature2 = receiver.getSignature("ciphertext.enc.sig2");

        // Verify the signatures
        if(signRSA.verify(signature1))
            System.out.println("Signature 1 verified");
        else
            System.out.println("Signature 1 verification failed");

        if(signRSA.verify(signature2))
            System.out.println("Signature 2 verified");
        else
            System.out.println("Signature 2 verification failed");

        // Print out the plaintext message
        System.out.printf("""

                        ===================
                        message
                        ===================

                        %s
                        """,
                            plaintext);
    }
}
