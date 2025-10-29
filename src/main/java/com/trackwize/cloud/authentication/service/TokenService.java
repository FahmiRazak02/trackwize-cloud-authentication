package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.constant.TokenConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.mapper.TokenMapper;
import com.trackwize.cloud.authentication.mapstruct.TokenMapStruct;
import com.trackwize.cloud.authentication.model.dto.EmailReqDTO;
import com.trackwize.cloud.authentication.model.dto.TokenReqDTO;
import com.trackwize.cloud.authentication.model.entity.Token;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.JWTUtil;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final EmailService emailService;
    private final TokenMapper tokenMapper;
    private final TokenMapStruct tokenMapStruct;
    private final JWTUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;

    public String generateToken(User user, int accessTokenTimeout) {
        log.info("---------- generateToken() ----------");

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());

        return jwtUtil.generateToken(claims, user.getUserId().toString(), accessTokenTimeout);
    }

    public int persistTokenRecord(TokenReqDTO tokenReqDTO) {
        log.info("---------- persistTokenRecord() ----------");
        Token token = tokenMapStruct.toEntity(tokenReqDTO);

        boolean isTokenExist = tokenMapper.isExist(token.getUserId());
        if (isTokenExist) {
            token.setUpdatedBy(tokenReqDTO.getUserId());
            return tokenMapper.update(token);
        }

        token.setCreatedBy(tokenReqDTO.getUserId());
        return tokenMapper.create(token);

    }

    public boolean isActiveSession(User user) {
        log.info("---------- isActiveSession() ----------");

        Token token = tokenMapper.findByUserId(user.getUserId());
        String accessToken = token.getAccessToken();
        if (accessToken.isEmpty()) {
            return false;
        }

        return jwtUtil.validateToken(accessToken);
    }

    public Token findByUserId(Long userId) {
        log.info("---------- findByUserId() ----------");
        return tokenMapper.findByUserId(userId);
    }

    public void logout(String refreshToken) {
        Token token = tokenMapper.validateToken(refreshToken);
        if (token != null) {
            tokenMapper.deleteById(token.getTokenId());
        }
    }

    public String generatePasswordResetToken(String email) throws TrackWizeException, MessagingException {
        log.info("---------- generatePasswordResetToken() ----------");

        String token = jwtUtil.generateToken(null, email, TokenConst.RESET_PASSWORD_TOKEN_EXPIRY);
        if (token == null) {
            throw new TrackWizeException(
                    ErrorConst.GENERATE_TOKEN_ERROR_CODE,
                    ErrorConst.GENERATE_TOKEN_ERROR_MSG
            );
        }
        redisTemplate.opsForValue().set(token, email, TokenConst.RESET_PASSWORD_TOKEN_EXPIRY, TimeUnit.MINUTES);

        EmailReqDTO reqDTO = getEmailReqDTO(email, token);
        emailService.sendEmail(reqDTO);

        return token;
    }

    private static EmailReqDTO getEmailReqDTO(String email, String token) {
        EmailReqDTO reqDTO = new EmailReqDTO();
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Password Reset for TrackWize");

        Map<String, Object> contents = new HashMap<>();
        contents.put("title", "Password Reset Request");
        contents.put("message", "Click the link below to reset your password:");
        contents.put("link", "http://localhost:8080/auth/reset-password?token=" + token);
        contents.put("expiry", TokenConst.RESET_PASSWORD_TOKEN_EXPIRY);

        reqDTO.setContents(contents);
        return reqDTO;
    }
}
