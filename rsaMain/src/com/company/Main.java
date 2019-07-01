package com.company;

import java.io.File;
import java.security.*;
import java.time.Duration;
import java.time.Instant;



public class Main {




    public static void main(String... argv) throws Exception {
        //First generate a public/private key pair
        File file = new File("C:\\Users\\Emperor_orbitz\\IdeaProjects\\rsaMain\\src\\files\\test-file\\20kb.txt");

        KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();


        //Let's sign our message

        byte [] signature = sign(file, pair.getPrivate());
        readFile pre = new readFile();
        pre.saveByteArrayToFile(signature, file.getName());


        //Let's check the signature


        boolean isCorrect = verify(file, signature, pair.getPublic());



        System.out.println("Signature correct: " + isCorrect);
    }









    /*
     *
     *  GENERATE KEY PAIRS
     *
     *
     *
     * */




    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }







    /*
     *
     *  SIGN RSA SIGNATURE
     *
     *
     * */
    public static byte [] sign(File file, PrivateKey privateKey) throws Exception {


        readFile pre = new readFile();
        byte [] message = pre.readFileToByteArray(file);
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(message);

        Instant startSign = Instant.now();
        byte[] signature = privateSignature.sign();
        Instant stopSign = Instant.now();
        Duration timeElapsed = Duration.between(startSign , stopSign);

        System.out.println("TIME FOR SIGNING IS: " + timeElapsed.toMillis()+ " milliseconds" );

        return signature;
    }








    /*
    *
    *  VERIFY RSA SIGNATURE
    *
    * */




    public static boolean verify(File file, byte [] signatureBytes, PublicKey publicKey) throws Exception {

        readFile pre = new readFile();

        byte [] fileInBytes = pre.readFileToByteArray(file);

        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(fileInBytes);


        // byte[] signatureBytes = Base64.getDecoder().decode(signature);

        Instant startVer = Instant.now();

        boolean trufa = publicSignature.verify(signatureBytes);
        Instant stopVer = Instant.now();
        Duration timeElapsedVer = Duration.between(startVer , stopVer);

        System.out.println("TIME FOR VERIFYING IS: " + timeElapsedVer.toMillis()+ " Milliseconds" );

        return trufa;
    }




}