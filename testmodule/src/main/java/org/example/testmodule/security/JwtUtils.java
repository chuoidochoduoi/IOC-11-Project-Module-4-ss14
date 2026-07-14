package org.example.testmodule.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.example.testmodule.config.JwtProperties;
import org.example.testmodule.entity.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtils {
    private final JwtProperties jwtProperties;
    private final Key key;

    public JwtUtils(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }

    public String generateAccessToken(User user) {
        Date expiryDate = new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration());
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("roles", user.getRole())
                .claim("userId", user.getId())
                .setId(jti)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }
}