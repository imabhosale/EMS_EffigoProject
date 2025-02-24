package com.ems.service.serviceImpl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * For Setting up KeyPairs for sending and receiving encrypted payload
 * Resource for Setting up RSA : <a href="https://www.baeldung.com/java-rsa">Baeldung java-rsa</a>
 */
@Service
@Slf4j
public class EncryptionService {
    // Get Public key
    // Get Private Key
    // Encrypt text
    // Decrypt text

    String algorithm;
    KeyPairGenerator generator;
    KeyPair keyPair;
    Cipher encryptCipher;
    Cipher decryptCipher;

    EncryptionService() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        this.algorithm = "RSA";
        this.generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        log.info("Created KeyPairGenerator : {}", generator.getAlgorithm());

        this.keyPair = generator.generateKeyPair();
        log.info("Generating KeyPairs (reference): {}", keyPair.toString());

        log.info("Generated Public Key: {}", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        log.info("Generated Private Key: {}",Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        encryptCipher = Cipher.getInstance(algorithm);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        log.info("Created Encrypt Cipher Instance (Reference) : {}", encryptCipher);

        decryptCipher = Cipher.getInstance(algorithm);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        log.info("Created Decrypt Cipher Instance (Reference) : {}", decryptCipher);

        log.info("Algorithms");
        log.info("KeyPairGen: {}", generator.getAlgorithm());
        log.info("Encrypt Cipher: {}", encryptCipher.getAlgorithm());
        log.info("Decrypt Cipher: {}", decryptCipher.getAlgorithm());

        log.info("EncryptService Created Successfully");
    }

    /**
     * Encrypts the string message and returns the base64 encoded crypt.
     */
    public String encryptMessage(String message) throws IllegalBlockSizeException, BadPaddingException {
        var encryptedMessage = encryptCipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    /**
     * Decrypt the encrypted message (Encoded in Base64) and return the original String
     */
    public String decodeMessage(String message) throws IllegalBlockSizeException, BadPaddingException {
       log.info("Preparing to decode the message...");
        var decodedMessage = Base64.getDecoder().decode(message);
        log.debug("Size of message up received decoding: {}", decodedMessage.length);
        return new String(decryptCipher.doFinal(decodedMessage));
    }

    public String getPrivateKey(){
        return Base64.getEncoder().encodeToString(this.keyPair.getPrivate().getEncoded());
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());
    }
}
