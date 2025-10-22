package com.trackwize.cloud.authentication.util;

import com.trackwize.cloud.authentication.constant.TokenConst;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;

import java.util.Collection;

public class CookieUtil {

    /**
     * Creates an HttpOnly cookie.
     */
    public static Cookie createCookie(String token, boolean secure, String name, int cookieTimeout) {
        Cookie cookie = new Cookie(name, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setMaxAge(TokenConst.BASE_TOKEN_EXPIRY * cookieTimeout);
        cookie.setPath(TokenConst.TOKEN_PATH);
        return cookie;
    }

    /**
     * Adds the SameSite attribute to cookies in the response.
     */
    public static void addSameSiteAttribute(HttpServletResponse response, String sameSiteValue) {
        Collection<String> headers = response.getHeaders(HttpHeaders.SET_COOKIE);
        boolean firstHeader = true;

        for (String header : headers) {
            String updatedHeader = String.format("%s; SameSite=%s", header, sameSiteValue);
            if (firstHeader) {
                response.setHeader(HttpHeaders.SET_COOKIE, updatedHeader);
                firstHeader = false;
            } else {
                response.addHeader(HttpHeaders.SET_COOKIE, updatedHeader);
            }
        }
    }
}
