package com.trackwize.cloud.authentication.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;

import java.util.Collection;

public class CookieUtil {

    private static final String TOKEN_NAME = "auth_token";
    private static final int TOKEN_EXPIRY = 60 * 60; // 1 hour
    private static final String TOKEN_PATH = "/";

    /**
     * Creates an HttpOnly cookie.
     */
    public static Cookie createCookie(String token, boolean secure) {
        Cookie cookie = new Cookie(TOKEN_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setMaxAge(TOKEN_EXPIRY);
        cookie.setPath(TOKEN_PATH);
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
