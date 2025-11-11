package com.trackwize.cloud.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.cloud.authentication.config.TokenSecurityConfig;
import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.constant.TokenConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.cloud.authentication.model.dto.AuthenticationResDTO;
import com.trackwize.cloud.authentication.model.dto.EncryptResDTO;
import com.trackwize.cloud.authentication.service.AuthenticationService;
import com.trackwize.cloud.authentication.service.TokenService;
import com.trackwize.cloud.authentication.util.CookieUtil;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.ResponseUtil;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final TokenService tokenService;
    private final TokenSecurityConfig tokenSecurityConfig;

    @PostMapping("/encrypt/{password}")
    public ResponseUtil encryptPassword(
            @PathVariable String password
    ){
        log.info("Request Payload [Password]: {}", password);

        String key = EncryptUtil.generateRandomKey(4);
        String encrytedPassword = EncryptUtil.encrypt(password, key);

        EncryptResDTO resDTO = new EncryptResDTO();
        resDTO.setKey(key);
        resDTO.setEncryptedPassword(encrytedPassword);

        ResponseUtil responseUtil = ResponseUtil.success();
        responseUtil.setData(resDTO);
        return responseUtil;
    }

    @PostMapping("/login")
    public ResponseUtil login(
            @ModelAttribute("trackingId") String trackingId,
            @RequestBody AuthenticationReqDTO reqDTO,
            HttpServletResponse response
    ) throws TrackWizeException {
        ResponseUtil resUtil = ResponseUtil.failure();
        log.info("Request Payload [AuthenticationReqDTO]: {}", reqDTO);

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

        ResponseUtil responseUtil = ResponseUtil.success();
        responseUtil.setData(resDTO);
        return responseUtil;
    }

    @PostMapping("/refresh")
    public ResponseUtil refreshToken (
            @ModelAttribute("trackingId") String trackingId,
            @ModelAttribute("userId") String userId,
            @CookieValue(name = TokenConst.REFRESH_TOKEN_NAME, required = false) String refreshToken,
            HttpServletResponse response
    ) throws TrackWizeException {
        ResponseUtil resUtil = ResponseUtil.success();
        Long userIdL = Long.parseLong(userId);

        if (refreshToken == null) {
            throw new TrackWizeException(
                    ErrorConst.MISSING_REFRESH_TOKEN_CODE,
                    ErrorConst.MISSING_REFRESH_TOKEN_MSG
            );
        }

        boolean isValid = authenticationService.verifyRefreshToken(userIdL, refreshToken);
        if (!isValid) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_REFRESH_TOKEN_CODE,
                    ErrorConst.INVALID_REFRESH_TOKEN_MSG
            );
        }

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

        tokenService.logout(refreshToken);
        return responseUtil;
    }

    @PostMapping("password-reset/request")
    public ResponseUtil requestPasswordReset(
            @ModelAttribute("trackingId") String trackingId,
            @RequestParam String email
    ) throws TrackWizeException, MessagingException, JsonProcessingException {
        log.info("Request Payload [Email]: {}", email);
        ResponseUtil responseUtil = ResponseUtil.success();

        String token = tokenService.generatePasswordResetToken(email, trackingId);

        responseUtil.setData(token);
        return responseUtil;
    }

}
