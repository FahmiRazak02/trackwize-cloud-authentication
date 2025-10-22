package com.trackwize.cloud.authentication.controller;

import com.trackwize.cloud.authentication.config.TokenSecurityConfig;
import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.constant.TokenConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.cloud.authentication.model.dto.AuthenticationResDTO;
import com.trackwize.cloud.authentication.model.dto.EncryptResDTO;
import com.trackwize.cloud.authentication.service.AuthenticationService;
import com.trackwize.cloud.authentication.util.CookieUtil;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.ResponseUtil;
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
    private final TokenSecurityConfig tokenSecurityConfig;

    @PostMapping("/encrypt/{password}")
    public ResponseUtil encryptPassword(
            @ModelAttribute("trackingId") String trackingId,
            @ModelAttribute("userId") String userId,
            @PathVariable String password
    ){
        log.info("---------- Password Encryption Request Received ----------");
        String key = EncryptUtil.generateRandomKey(4);
        String encrytedPassword = EncryptUtil.encrypt(password, key);

        EncryptResDTO resDTO = new EncryptResDTO();
        resDTO.setKey(key);
        resDTO.setEncryptedPassword(encrytedPassword);

        log.info("---------- Password Encryption Request Success ----------");
        ResponseUtil responseUtil = ResponseUtil.success();
        responseUtil.setData(resDTO);
        return responseUtil;
    }

    @PostMapping("/login")
    public ResponseUtil login(
            @ModelAttribute("trackingId") String trackingId,
            @ModelAttribute("userId") String userId,
            @RequestBody AuthenticationReqDTO reqDTO,
            HttpServletResponse response
    ) {
        ResponseUtil resUtil = ResponseUtil.failure();
        log.info("---------- Authentication Request Received ----------");

        try {
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

            log.info("---------- Authentication Request Success ----------");
            ResponseUtil responseUtil = ResponseUtil.success();
            responseUtil.setData(resDTO);
            return responseUtil;

        } catch (TrackWizeException e) {
            log.info("TrackWizeException occur: ", e);
            return ResponseUtil.createErrorResponse(
                    e.getMessageCode(),
                    e.getMessage()
            );
        } catch (Exception e) {
            log.info("Exception occur: ", e);
            return ResponseUtil.createErrorResponse(
                    ErrorConst.AUTHENTICATION_ERROR_CODE,
                    ErrorConst.AUTHENTICATION_ERROR_MSG
            );
        }
    }

    //todo refresh api
    public ResponseUtil refreshToken (
            @ModelAttribute("trackingId") String trackingId,
            @ModelAttribute("userId") String userId,
            @CookieValue(name = TokenConst.REFRESH_TOKEN_NAME, required = false) String refreshToken,
            HttpServletResponse response
    ) {
        log.info("---------- Token Refresh Request Received ----------");
        ResponseUtil resUtil = ResponseUtil.failure();
        try {
            if (refreshToken == null) {
                throw new TrackWizeException(
                        ErrorConst.MISSING_REFRESH_TOKEN_CODE,
                        ErrorConst.MISSING_REFRESH_TOKEN_MSG
                );
            }

            boolean isValid = authenticationService.verifyRefreshToken(userId, refreshToken);
            if (!isValid) {
                throw new TrackWizeException(
                        ErrorConst.INVALID_REFRESH_TOKEN_CODE,
                        ErrorConst.INVALID_REFRESH_TOKEN_MSG
                );
            }

            String token = authenticationService.generateNewAccessToken(userId);
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

            resUtil = ResponseUtil.success();
            resUtil.setData(token);
            log.info("---------- Token Refresh Success ----------");
            return ResponseUtil.success();

        } catch (TrackWizeException e) {
            log.info("TrackWizeException occur: ", e);
            return ResponseUtil.createErrorResponse(
                    e.getMessageCode(),
                    e.getMessage()
            );
        } catch (Exception e) {
            log.info("Exception occur: ", e);
            return ResponseUtil.createErrorResponse(
                    ErrorConst.AUTHENTICATION_ERROR_CODE,
                    ErrorConst.AUTHENTICATION_ERROR_MSG
            );
        }
    }

    //todo logout api
    // @PostMapping("logout")


    //todo forgot password api

}
