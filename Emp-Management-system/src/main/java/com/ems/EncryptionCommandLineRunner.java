package com.ems;

import com.ems.service.serviceImpl.EncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class EncryptionCommandLineRunner implements CommandLineRunner {

    @Autowired
    EncryptionService encryptionService;

    @Override
    public void run(String... args) throws Exception {
        var message = "Hello";
        log.info("Original Message: {}", message);
        var encryptedMessage = encryptionService.encryptMessage(message);
        log.info("Encrypted Message: {}", encryptedMessage);
        var decryptedMessage = encryptionService.decodeMessage(encryptedMessage);
        log.info("Decrypted Message: {}", decryptedMessage);
    }
}
