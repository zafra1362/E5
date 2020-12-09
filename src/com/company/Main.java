package com.company;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        String Ruta = "C:\\Usuari\\Dylan\\Escriptori\\DAM\\2nDAM\\M09\\PROJECTES\\E5\\src\\com\\company\\.keystore";
        String keystoreContra = "2DAM";
        char[] passwordChar = keystoreContra.toCharArray();
        String certRuta = "C:\\Usuari\\Dylan\\Escriptori\\DAM\\2nDAM\\M09\\PROJECTES\\E5\\src\\com\\company\\profe.cer";

        // E1
        KeyPair parellaClaus = Xifrar.Gen(1024);
        PublicKey clauPublica = parellaClaus.getPublic();
        PrivateKey privateKey = parellaClaus.getPrivate();
        System.out.print("Text a xifrar: ");
        String text = scanner.nextLine();
        byte[] test = text.getBytes();
        byte[] xifrar = Xifrar.encryptData(test, clauPublica);
        byte[] desxifrar = Xifrar.decryptData(xifrar, privateKey);
        System.out.println(xifrar);
        System.out.println("Text desxifrat: " + new String(desxifrar));

        // E2.1 E2.2 E2.3 E2.4 E2.5
        System.out.println("Tipus: " + Xifrar.loadKeyStore(Ruta,keystoreContra).getType());
        System.out.println("Mida: " + Xifrar.loadKeyStore(Ruta,keystoreContra).size());
        System.out.println("Alias: " + Xifrar.loadKeyStore(Ruta,keystoreContra).aliases().nextElement());
        System.out.println("Certificat: " + Xifrar.loadKeyStore(Ruta,keystoreContra).getCertificate("lamevaclaum9"));
        System.out.println("Algoritme: " + Xifrar.loadKeyStore(Ruta,keystoreContra).getCertificate("lamevaclaum9").getPublicKey().getAlgorithm());

        // E3
        System.out.println(Xifrar.getPublicKey(certRuta));

        // E4
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream keyStoreData = new FileInputStream(Ruta)) {
            keyStore.load(keyStoreData, passwordChar);
            System.out.println(Xifrar.getPublicKey(keyStore,"lamevaclaum9",keystoreContra));
        }

        // E5
        byte[] testP ="Test".getBytes();
        System.out.println("Signatura: "+ new String(Xifrar.signData(testP,privateKey)));

        // E6
        byte[] sgnatura = Xifrar.signData(testP,privateKey);
        System.out.println("Validesa: "+ Xifrar.validateSignature(testP,sgnatura,clauPublica));

    }
}
