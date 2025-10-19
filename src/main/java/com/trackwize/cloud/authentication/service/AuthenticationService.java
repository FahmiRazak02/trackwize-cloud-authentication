package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.mapper.UserMapper;
import com.trackwize.cloud.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.cloud.authentication.model.dto.AuthenticationResDTO;
import com.trackwize.cloud.authentication.model.dto.TokenReqDTO;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.JWTUtil;
import com.trackwize.cloud.authentication.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    @Value("${jwt.defaultAccessTokenTimeout}")
    private String defaultAccessTokenTimeout;

    @Value("${jwt.defaultRefreshTokenTimeout}")
    private String defaultRefreshTokenTimeout;

    private final TokenService tokenService;
    private final UserMapper userMapper;
    private final JWTUtil jwtUtil;

    public AuthenticationResDTO validateCredentials(AuthenticationReqDTO reqDTO) throws TrackWizeException {
        log.info("---------- validateCredentials() ----------");
        AuthenticationResDTO resDTO = new AuthenticationResDTO();

        User user = userMapper.findByEmail(reqDTO.getEmail());
        if (user == null) {
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        boolean isPasswordMatch = validatePassword(reqDTO, user);
        if (!isPasswordMatch) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_CREDENTIALS_CODE,
                    ErrorConst.INVALID_CREDENTIALS_MSG
            );
        }

        boolean isActive = tokenService.hasActiveSession(user);
        if (isActive) {
            throw new TrackWizeException(
                    ErrorConst.USER_ALREADY_LOGGED_IN_CODE,
                    ErrorConst.USER_ALREADY_LOGGED_IN_MSG
            );
        }

        String accessToken = tokenService.generateToken(user, defaultAccessTokenTimeout);
        String refreshToken = tokenService.generateToken(user, defaultRefreshTokenTimeout);
        if (accessToken.isEmpty() || refreshToken.isEmpty()) {
            throw new TrackWizeException(
                    ErrorConst.GENERATE_TOKEN_ERROR_CODE,
                    ErrorConst.GENERATE_TOKEN_ERROR_MSG
            );
        }

        TokenReqDTO tokenReqDTO = new TokenReqDTO();
        tokenReqDTO.setUserId(user.getUserId());
        tokenReqDTO.setAccessToken(accessToken);
        tokenReqDTO.setRefreshToken(refreshToken);

        int result = tokenService.persistTokenRecord(tokenReqDTO);
        if (result <= 0) {
            throw new TrackWizeException(
                    ErrorConst.PERSIST_TOKEN_ERROR_CODE,
                    ErrorConst.PERSIST_TOKEN_ERROR_MSG
            );
        }

        resDTO.setAccessToken(accessToken);
        resDTO.setRefreshToken(refreshToken);
        return resDTO;
    }

    private boolean validatePassword(AuthenticationReqDTO reqDTO, User user) {
        log.info("---------- validatePassword() ----------");

        String encryptedPassword = EncryptUtil.decrypt(reqDTO.getEncryptedPassword(), reqDTO.getKey());
        return PasswordUtil.isPasswordMatch(encryptedPassword, user.getPassword());
    }
}
