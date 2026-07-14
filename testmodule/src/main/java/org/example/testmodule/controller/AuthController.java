package org.example.testmodule.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.testmodule.config.JwtProperties;
import org.example.testmodule.dto.JwtResponse;
import org.example.testmodule.dto.LoginRequest;
import org.example.testmodule.dto.TokenRefreshRequest;
import org.example.testmodule.entity.RefreshToken;
import org.example.testmodule.entity.User;
import org.example.testmodule.repository.RefreshTokenRepository;
import org.example.testmodule.repository.UserRepository;
import org.example.testmodule.security.JwtUtils;
import org.example.testmodule.security.RefreshTokenService;
import org.example.testmodule.security.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public AuthController(UserRepository userRepository, JwtUtils jwtUtils,
                          RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder,
                          TokenBlacklistService tokenBlacklistService, JwtProperties jwtProperties,
                          RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.tokenBlacklistService = tokenBlacklistService;
        this.jwtProperties = jwtProperties;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest loginRequest) {
        Optional<User> userOptional = userRepository.findByUsername(loginRequest.getUsername());

        if (userOptional.isEmpty() ||
            !passwordEncoder.matches(loginRequest.getPassword(), userOptional.get().getPassword())) {
            return ResponseEntity.badRequest().build();
        }

        User user = userOptional.get();
        String accessToken = jwtUtils.generateAccessToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return ResponseEntity.ok(new JwtResponse(
                accessToken,
                refreshToken.getToken(),
                user.getId(),
                user.getUsername(),
                user.getRole()
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(@RequestBody TokenRefreshRequest request) {
        try {
            JwtResponse newTokens = refreshTokenService.refreshToken(request.getRefreshToken());
            return ResponseEntity.ok(newTokens);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);
        Key key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String jti = claims.getId();
            Date exp = claims.getExpiration();

            // Tính TTL còn lại
            long ttl = exp.getTime() - System.currentTimeMillis();

            // Thêm vào blacklist
            tokenBlacklistService.addToBlacklist(jti, ttl);

            // Xóa refresh token tương ứng
            String username = claims.getSubject();
            Optional<User> userOptional = userRepository.findByUsername(username);
            if (userOptional.isPresent()) {
                refreshTokenRepository.deleteByUserId(userOptional.get().getId());
            }

            SecurityContextHolder.clearContext();
            return ResponseEntity.ok("Logged out successfully");

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid token");
        }
    }
}