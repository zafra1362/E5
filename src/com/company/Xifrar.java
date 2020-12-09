package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Xifrar {

    // E1.i
    public static KeyPair Gen(int generar) {
        KeyPair clau = null;
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("");
            keyGenerator.initialize(generar);
            clau = keyGenerator.genKeyPair();
        } catch (Exception ex) {
            System.err.println("No s'ha pogut generar");
        }
        return clau;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] ed = null;
        try {
            Cipher cipher = Cipher.getInstance("");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            ed =  cipher.doFinal(data);
        } catch (Exception error) {
            System.err.println("Error al xifrar: " + error);
        }
        return ed;
    }

    public static byte[] decryptData(byte[] data, PrivateKey pub) {
        byte[] dd = null;
        try {
            Cipher cipher = Cipher.getInstance("");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            dd =  cipher.doFinal(data);
        } catch (Exception  error) {
            System.err.println("Error al desxifrar: " + error);
        }
        return dd;
    }

    public static KeyStore loadKeyStore(String keyArxiu, String keyContra) throws Exception {
        KeyStore keystore = KeyStore.getInstance("");
        File arxiu = new File (keyArxiu);
        if (arxiu.isFile()) {
            FileInputStream in = new FileInputStream (arxiu);
            keystore.load(in, keyContra.toCharArray());
        }
        return keystore;
    }

    public static SecretKey keygenKeyGeneration(int llarg) {
        SecretKey sk = null;
        if ((llarg == 128) || (llarg == 192) || (llarg == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(llarg);
                sk = kgen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Error");
            }
        }
        return sk;
    }

    public static PublicKey getPublicKey(String arxiu) throws CertificateException, FileNotFoundException {
        CertificateFactory factory = CertificateFactory.getInstance("");
        FileInputStream acabar = new FileInputStream(arxiu);
        X509Certificate certificar = (X509Certificate)factory.generateCertificate(acabar);
        PublicKey publicKey = certificar.getPublicKey();
        return publicKey;
    }

    // E4
    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        FileInputStream fin = new FileInputStream("C:\\Usuari\\Dylan\\Escriptori\\DAM\\2nDAM\\M09\\PROJECTES\\E5\\src\\com\\company\\profe.cer");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)factory.generateCertificate(fin);
        PublicKey publickey = certificate.getPublicKey();
        return publickey;
    }

    // E5
    public static byte[] signData(byte[] data, PrivateKey clauprivada) {
        byte[] signar = null;
        try {
            Signature signatura = Signature.getInstance(" ");
            signatura.initSign(clauprivada);
            signatura.update(data);
            signar = signatura.sign();
        } catch (Exception error) {
            System.err.println("Error: " + error);
        }
        return signar;
    }

    // E6
    public static boolean validateSignature(byte[] data, byte[] firma, PublicKey pub) {
        boolean validesa = false;
        try {
            Signature signar = Signature.getInstance("SHA1withRSA");
            signar.initVerify(pub);
            signar.update(data);
            validesa = signar.verify(firma);
        } catch (Exception error) {
            System.err.println("Error: " + error);
        }
        return validesa;
    }
}

