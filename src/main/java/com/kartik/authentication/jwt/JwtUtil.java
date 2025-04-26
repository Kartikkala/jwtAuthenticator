package com.kartik.authentication.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {
    private final String KEY_PATH = System.getProperty("user.home") + "/.authenticator/secret.key";

    private Key getSigningKey() {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(KEY_PATH));
            byte[] decoded = Base64.getDecoder().decode(encoded);
            return Keys.hmacShaKeyFor(decoded);
        } catch (IOException e) {
            throw new RuntimeException("JWT Secret Key not found. Generate it first.", e);
        }
    }

    public String generateToken(String subject, Claims claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(getSigningKey())
                .compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody();
        return resolver.apply(claims);
    }
}
