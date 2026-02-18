package com.example.passkeyproxy.util;

import jakarta.servlet.http.HttpServletRequest;

public final class RequestUtil {

    private RequestUtil() {}

    /**
     * Determines the scheme://host origin from the request, respecting
     * X-Forwarded-Proto for reverse-proxy deployments.
     */
    public static String getOrigin(HttpServletRequest request) {
        String scheme;
        String forwarded = request.getHeader("X-Forwarded-Proto");
        if (forwarded != null && !forwarded.isBlank()) {
            scheme = forwarded.trim().split(",")[0].trim(); // take first value if comma-separated
        } else if (request.isSecure()) {
            scheme = "https";
        } else {
            scheme = "http";
        }
        return scheme + "://" + request.getHeader("Host");
    }

    /**
     * Returns the real client IP, respecting X-Real-IP and X-Forwarded-For headers.
     */
    public static String getClientIp(HttpServletRequest request) {
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
