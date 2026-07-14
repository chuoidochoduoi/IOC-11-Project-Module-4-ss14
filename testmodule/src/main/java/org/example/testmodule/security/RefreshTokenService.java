package org.example.testmodule.security;

import org.example.testmodule.config.JwtProperties;
import org.example.testmodule.dto.JwtResponse;
import org.example.testmodule.entity.RefreshToken;
import org.example.testmodule.entity.User;
import org.example.testmodule.repository.RefreshTokenRepository;
import org.example.testmodule.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtProperties jwtProperties, JwtUtils jwtUtils, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
    }

    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Instant expiryDate = Instant.now().plusMillis(jwtProperties.getRefreshTokenExpiration());
        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(expiryDate);
        refreshToken.setToken(token);

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token has expired");
        }
        return token;
    }

    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));
    }

    @Transactional
    public JwtResponse refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB
        RefreshToken refreshToken = findByToken(requestToken);

        // 2. Kiểm tra hết hạn
        verifyExpiration(refreshToken);

        // 3. Rotation: Xóa Refresh Token cũ
        refreshTokenRepository.delete(refreshToken);

        // 4. Lấy User từ token cũ (dùng userId để fetch user đầy đủ)
        Long userId = refreshToken.getUser().getId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 5. Tạo Access Token mới
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // 6. Tạo Refresh Token mới
        RefreshToken newRefreshToken = createRefreshToken(user.getId());

        // 7. Trả về cặp token mới
        return new JwtResponse(
                newAccessToken,
                newRefreshToken.getToken(),
                user.getId(),
                user.getUsername(),
                user.getRole()
        );
    }
}