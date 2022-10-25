package com.oop;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;

@SuppressWarnings("ResultOfMethodCallIgnored")
public class Receiver {

    private Cipher decoder;
    final static String keyStoreName = "lab1Store";
    private final static char[] keyStorePassword = "lab1StorePass".toCharArray();
    private final static String alias = "lab1EncKeys";
    final static char[] aliasPassword = "lab1KeyPass".toCharArray();

    public void setDecoder(String type) throws Exception {
        this.decoder = Cipher.getInstance(type);
    }

    public void init_decoder(byte[] key, byte[] IV) throws Exception {

        SecretKeySpec k = new SecretKeySpec(key, "AES");
        IvParameterSpec iv = new IvParameterSpec(IV);

        decoder.init(Cipher.DECRYPT_MODE, k, iv);
    }

    public void init_decoder(PrivateKey key) throws Exception {
        decoder.init(Cipher.DECRYPT_MODE, key);
    }

    public byte[] decrypt(byte[] data) throws Exception {
        return decoder.doFinal(data);
    }

    public PrivateKey getPrivateKey() throws Exception {
        // Get private key from the keystore
        KeyStore keystore = KeyStore.getInstance(new File(keyStoreName), keyStorePassword);
        ProtectionParameter entryPassword = new KeyStore.PasswordProtection(aliasPassword);

        // get the private key from the entry
        PrivateKeyEntry entry = (PrivateKeyEntry) keystore.getEntry(alias, entryPassword);

        // return the key
        return entry.getPrivateKey();
    }

    public byte[] getSignature(String path){
        byte[] signature = null;

        try{
            FileInputStream fis = new FileInputStream("ciphertext.enc.sig1");
            signature = new byte[fis.available()];
            fis.read(signature);
        }
        catch(IOException e){
            e.printStackTrace();
        }
        return signature;
    }

    public byte[] extractBytes(String path, int length, int offset) throws IOException {
        // Create input stream from file
        FileInputStream fs = new FileInputStream(path);
        // Create byte[] to hold the value
        byte[] data = new byte[length];
        // Set offset index
        fs.skip(offset);
        // Copy bytes to byte[]
        fs.read(data);
        // Return byte[]
        return data;
    }

    public byte[] extractBytes(String path, int offset) throws IOException {
        // Create input stream from ciphertext file
        FileInputStream fs = new FileInputStream(path);
        // Set message length
        int length = fs.available() - offset;
        // Create byte[] to hold the value
        byte[] data = new byte[length];
        // Set offset index
        fs.skip(offset);
        // Copy bytes to byte[]
        fs.read(data);

        return data;
    }
}