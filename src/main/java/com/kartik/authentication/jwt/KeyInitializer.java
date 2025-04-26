package com.kartik.authentication.jwt;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.util.Base64;

import io.jsonwebtoken.security.Keys;

@Component
public class KeyInitializer implements CommandLineRunner {

    private static final String PATH = System.getProperty("user.home") + "/.authenticator/secret.key";

    @Override
    public void run(String... args) throws Exception {
        File keyFile = new File(PATH);
        if (!keyFile.exists()) {
            keyFile.getParentFile().mkdirs();
            Key key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
            String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());

            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(encodedKey.getBytes());
            }

            System.out.println("🔑 New secret key generated at: " + PATH);
        } else {
            System.out.println("🔑 Secret key already exists at: " + PATH);
        }
    }
}
