package org.example.testmodule.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {
    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void addToBlacklist(String jti, long ttlMillis) {
        String key = "blacklist:" + jti;
        redisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
    }

    public boolean isBlacklisted(String jti) {
        String key = "blacklist:" + jti;
        return redisTemplate.hasKey(key);
    }
}