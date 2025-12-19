package com.trackwize.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.authentication.config.TokenSecurityConfig;
import com.trackwize.common.constant.ErrorConst;
import com.trackwize.common.constant.TokenConst;
import com.trackwize.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.authentication.model.dto.AuthenticationResDTO;
import com.trackwize.authentication.model.dto.EncryptResDTO;
import com.trackwize.authentication.model.dto.ResetRequestDTO;
import com.trackwize.authentication.service.AuthenticationService;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.CookieUtil;
import com.trackwize.common.util.ResponseUtil;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final TokenSecurityConfig tokenSecurityConfig;

    /**
     * Encrypt the given password and generate a random key.
     *
     * @param password The password to be encrypted.
     * @return A ResponseUtil containing an EncryptResDTO with the encryption key and the encrypted password.
     */
    @PostMapping("encrypt/{password}")
    public ResponseUtil encryptPassword(
            @PathVariable String password
    ){
        ResponseUtil responseUtil = ResponseUtil.success();

        EncryptResDTO resDTO = authenticationService.encrypt(password);

        responseUtil.setData(resDTO);
        return responseUtil;
    }

    /**
     * Authenticate user and generate access and refresh tokens.
     *
     * @param reqDTO The authentication request data transfer object containing user credentials.
     * @return A ResponseUtil containing an AuthenticationResDTO with the generated access and refresh tokens.
     * @throws TrackWizeException If authentication fails or there is an error during token generation.
     */
    @PostMapping("login")
    public ResponseUtil login(
            @ModelAttribute("trackingId") String trackingId,
            @RequestBody AuthenticationReqDTO reqDTO,
            HttpServletResponse response
    ) throws TrackWizeException {
        log.info("Request Payload [AuthenticationReqDTO]: {}", reqDTO);
        ResponseUtil responseUtil = ResponseUtil.success();

        AuthenticationResDTO resDTO = authenticationService.authenticateAccess(reqDTO);
        if (tokenSecurityConfig.isTokenCookieEnable()) {
            Cookie accessCookie = CookieUtil.createCookie(
                    resDTO.getAccessToken(),
                    tokenSecurityConfig.isHttps(),
                    TokenConst.ACCESS_TOKEN_NAME,
                    TokenConst.ACCESS_TOKEN_EXPIRY
            );
            Cookie refreshCookie = CookieUtil.createCookie(
                    resDTO.getRefreshToken(),
                    tokenSecurityConfig.isHttps(),
                    TokenConst.REFRESH_TOKEN_NAME,
                    TokenConst.REFRESH_TOKEN_EXPIRY
            );
            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);
            CookieUtil.addSameSiteAttribute(response, "Lax");
        }

        responseUtil.setData(resDTO);
        return responseUtil;
    }

    /**
     * Refresh the access token using the provided refresh token.
     *
     * @param userId       The ID of the user.
     * @param refreshToken The refresh token to be validated.
     * @return A ResponseUtil containing the new access token.
     * @throws TrackWizeException If the refresh token is missing or invalid.
     */
    @PostMapping("refresh")
    public ResponseUtil refreshToken (
            @ModelAttribute("trackingId") String trackingId,
            @ModelAttribute("userId") String userId,
            @CookieValue(name = TokenConst.REFRESH_TOKEN_NAME, required = false) String refreshToken,
            HttpServletResponse response
    ) throws TrackWizeException {
        ResponseUtil resUtil = ResponseUtil.success();
        Long userIdL = Long.parseLong(userId);

        if (StringUtils.isBlank(refreshToken)) {
            throw new TrackWizeException(
                    ErrorConst.MISSING_REFRESH_TOKEN_CODE,
                    ErrorConst.MISSING_REFRESH_TOKEN_MSG
            );
        }

        authenticationService.validateRefreshToken(userIdL, refreshToken);

        String token = authenticationService.generateNewAccessToken(userIdL);
        if (tokenSecurityConfig.isTokenCookieEnable()) {
            Cookie accessCookie = CookieUtil.createCookie(
                    token,
                    tokenSecurityConfig.isHttps(),
                    TokenConst.ACCESS_TOKEN_NAME,
                    TokenConst.ACCESS_TOKEN_EXPIRY
            );
            response.addCookie(accessCookie);
            CookieUtil.addSameSiteAttribute(response, "Lax");
        }

        resUtil.setData(token);
        return resUtil;
    }

    /**
     * Logout the user by invalidating the refresh token.
     *
     * @param refreshToken The refresh token to be invalidated.
     * @return A ResponseUtil indicating successful logout.
     * @throws TrackWizeException If the refresh token is missing.
     */
    @PostMapping("logout")
    public ResponseUtil logout(
            @ModelAttribute("trackingId") String trackingId,
            @CookieValue(name = TokenConst.REFRESH_TOKEN_NAME, required = false) String refreshToken,
            HttpServletResponse response
    ) throws TrackWizeException {
        ResponseUtil responseUtil = ResponseUtil.success();
        if (refreshToken == null) {
            throw new TrackWizeException(
                    ErrorConst.MISSING_REFRESH_TOKEN_CODE,
                    ErrorConst.MISSING_REFRESH_TOKEN_MSG
            );
        }

        if (tokenSecurityConfig.isTokenCookieEnable()) {
            Cookie accessCookie = CookieUtil.removeTokenFromCookie(
                    tokenSecurityConfig.isHttps(),
                    TokenConst.ACCESS_TOKEN_NAME
            );
            Cookie refreshCookie = CookieUtil.removeTokenFromCookie(
                    tokenSecurityConfig.isHttps(),
                    TokenConst.REFRESH_TOKEN_NAME
            );
            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);
        }

        authenticationService.logout(refreshToken);
        return responseUtil;
    }

    /**
     * Request a password reset token for the specified email.
     *
     * @param email The email address of the user requesting a password reset.
     * @return A ResponseUtil containing the generated password reset token.
     * @throws TrackWizeException      If there is an error during token generation.
     * @throws MessagingException      If there is an error sending the reset email.
     * @throws JsonProcessingException If there is an error processing JSON.
     */
    @PostMapping("password-reset/request")
    public ResponseUtil requestPasswordReset(
            @ModelAttribute("trackingId") String trackingId,
            @RequestParam String email
    ) throws TrackWizeException, MessagingException, JsonProcessingException {
        log.info("Request Payload [Email]: {}", email);
        ResponseUtil responseUtil = ResponseUtil.success();

        String token = authenticationService.generatePasswordResetToken(email, trackingId);

        responseUtil.setData(token);
        return responseUtil;
    }

    /**
     * Process the password reset using the provided reset request data.
     *
     * @param reqDTO The reset request data transfer object containing the reset token and new password.
     * @return A ResponseUtil indicating successful password reset.
     * @throws TrackWizeException If there is an error during password update.
     */
    @PostMapping("password-reset/process")
    public ResponseUtil processPasswordReset(
            @ModelAttribute("trackingId") String trackingId,
            @RequestBody ResetRequestDTO reqDTO
    ) throws TrackWizeException {
        log.info("Request Payload [ResetRequestDTO]: {}", reqDTO);
        ResponseUtil responseUtil = ResponseUtil.success();

        authenticationService.updatePassword(reqDTO);
        return responseUtil;
    }

}
