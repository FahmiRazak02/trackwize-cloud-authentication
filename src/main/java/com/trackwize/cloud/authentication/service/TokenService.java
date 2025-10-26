package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.mapper.TokenMapper;
import com.trackwize.cloud.authentication.mapstruct.TokenMapStruct;
import com.trackwize.cloud.authentication.model.dto.TokenReqDTO;
import com.trackwize.cloud.authentication.model.entity.Token;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenMapper tokenMapper;
    private final TokenMapStruct tokenMapStruct;
    private final JWTUtil jwtUtil;

    public String generateToken(User user, String accessTokenTimeout) {
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

        if (!jwtUtil.validateToken(accessToken)) {
            return false;
        }

        return true;
    }

    public Token findByUserId(Long userId) {
        log.info("---------- findByUserId() ----------");
        return tokenMapper.findByUserId(userId);
    }
}
