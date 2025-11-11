package com.trackwize.cloud.authentication.controller.base;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;


@ControllerAdvice
public class GlobalControllerAdvice {

    @ModelAttribute("trackingId")
    public String trackingId(HttpServletRequest request) {
        String header = request.getHeader("X-Tracking-ID");
        if (header == null) {
            Object attr = request.getAttribute("X-Tracking-ID");
            return attr != null ? attr.toString() : null;
        }
        return header;
    }

    @ModelAttribute("userId")
    public String userId(HttpServletRequest request) {
        return request.getHeader("X-User-ID");
    }

    @ModelAttribute("token")
    public String jwtKey(HttpServletRequest request) {
        return request.getHeader("key");
    }
}
