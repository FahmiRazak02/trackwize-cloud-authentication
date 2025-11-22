package com.trackwize.cloud.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.mapper.UserMapper;
import com.trackwize.cloud.authentication.model.dto.*;
import com.trackwize.cloud.authentication.model.entity.Token;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.JWTUtil;
import com.trackwize.cloud.authentication.util.PasswordUtil;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    @Value("${jwt.defaultAccessTokenTimeout}")
    private int defaultAccessTokenTimeout;

    @Value("${jwt.defaultRefreshTokenTimeout}")
    private int defaultRefreshTokenTimeout;

    private final TokenService tokenService;
    private final UserService userService;
    private final UserMapper userMapper;
    private final JWTUtil jwtUtil;

    /**
     * Encrypt the given password and generate a random key.
     *
     * @param password The password to be encrypted.
     * @return An EncryptResDTO containing the encryption key and the encrypted password.
     */
    public EncryptResDTO encrypt(String password) {
//        Generate random key, encrypt the password and EncryptResDTO as response
        String key = EncryptUtil.generateRandomKey(4);
        String encryptedPassword = EncryptUtil.encrypt(password, key);
        return new EncryptResDTO(key, encryptedPassword);
    }

    /**
     * Authenticate user and generate access and refresh tokens.
     *
     * @param reqDTO The authentication request data transfer object containing user credentials.
     * @return An AuthenticationResDTO containing the generated access and refresh tokens.
     * @throws TrackWizeException If authentication fails or there is an error during token generation.
     */
    public AuthenticationResDTO authenticateAccess(AuthenticationReqDTO reqDTO) throws TrackWizeException {
//        1. Retrieve user (throws TrackWizeException if not found)
        User user = userService.getUserByEmail(reqDTO.getEmail());

//        2. Validate password (throws TrackWizeException if invalid)
        userService.validatePassword(reqDTO, user);

//        3. Ensure no concurrent active session (throws TrackWizeException if already logged in)
        tokenService.validateNoActiveSession(user);

//        4. Generate JWT tokens
        String accessToken = tokenService.generateToken(user, defaultAccessTokenTimeout);
        String refreshToken = tokenService.generateToken(user, defaultRefreshTokenTimeout);

        TokenReqDTO tokenReqDTO = new TokenReqDTO();
        tokenReqDTO.setUserId(user.getUserId());
        tokenReqDTO.setAccessToken(accessToken);
        tokenReqDTO.setRefreshToken(refreshToken);

//        5. Save token record to database
        tokenService.saveTokenRecord(tokenReqDTO);

//        6. Return AuthenticationResDTO as response
        return new AuthenticationResDTO(accessToken, refreshToken);
    }


    /**
     * Validate the provided refresh token for the specified user.
     *
     * @param userId       The ID of the user.
     * @param refreshToken The refresh token to be validated.
     * @throws TrackWizeException If the refresh token is invalid.
     */
    public void validateRefreshToken(Long userId, String refreshToken) {
        boolean isValid = tokenService.validateRefreshToken(userId, refreshToken);
        if (!isValid) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_REFRESH_TOKEN_CODE,
                    ErrorConst.INVALID_REFRESH_TOKEN_MSG
            );
        }
    }

    /**
     * Generate a new access token for the specified user.
     *
     * @param userId The ID of the user.
     * @return The newly generated access token.
     * @throws TrackWizeException If there is an error during token generation.
     */
    public String generateNewAccessToken(Long userId) throws TrackWizeException {
        User user = userMapper.findById(userId);
        return tokenService.generateToken(user, defaultAccessTokenTimeout);
    }

    /**
     * Update the user's password using the provided reset request data.
     *
     * @param reqDTO The reset request data transfer object containing the reset token and new password.
     * @throws TrackWizeException If there is an error during password update.
     */
    public void updatePassword(ResetRequestDTO reqDTO) throws TrackWizeException {
        String email = tokenService.getRedisValueByToken(reqDTO.getToken());
        if (StringUtils.isBlank(email)){
            log.info("{} due to: Invalid or expired reset token.", ErrorConst.TOKEN_EXPIRED_CODE);
            throw new TrackWizeException(
                    ErrorConst.TOKEN_EXPIRED_CODE,
                    ErrorConst.TOKEN_EXPIRED_MSG
            );
        }

        User user = userMapper.findByEmail(email);
        if (ObjectUtils.isEmpty(user)) {
            log.info("{} due to: No user record found for this email {}.", ErrorConst.NO_RECORD_FOUND_CODE, email);
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        user.setPassword(PasswordUtil.encryptPassword(EncryptUtil.decrypt(reqDTO.getEncryptedPassword(), reqDTO.getKey())));
        int result = userMapper.updatePassword(user);
        if (result <= 0) {
            log.info("{} due to: Failed to update new password.", ErrorConst.UPDATE_PASSWORD_FAILED_CODE);
            throw new TrackWizeException(
                    ErrorConst.UPDATE_PASSWORD_FAILED_CODE,
                    ErrorConst.UPDATE_PASSWORD_FAILED_MSG
            );
        }

    }

    /**
     * Generate a password reset token for the specified email.
     *
     * @param email      The email address of the user.
     * @param trackingId The tracking ID for the request.
     * @return The generated password reset token.
     * @throws TrackWizeException      If there is an error during token generation.
     * @throws JsonProcessingException If there is an error processing JSON.
     */
    public String generatePasswordResetToken(String email, String trackingId) throws TrackWizeException, JsonProcessingException {
        return tokenService.generatePasswordResetToken(email, trackingId);
    }

    /**
     * Logout the user by invalidating the provided refresh token.
     *
     * @param refreshToken The refresh token to be invalidated.
     */
    public void logout(String refreshToken) {
        tokenService.logout(refreshToken);
    }
}
