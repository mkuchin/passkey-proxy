package com.example.passkeyproxy.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Proxy configuration loaded from config/config.yml.
 */
public class ProxySettings {

    private String rpDisplayName = "MyCompany";
    private String rpId = "localhost";
    private List<String> rpOrigins = new ArrayList<>();

    /**
     * When true, registrations are immediately activated without admin approval.
     * WARNING: Do not enable in production — anyone can self-register.
     */
    private boolean testMode = false;

    private int sessionSoftTimeoutSeconds = 28800;   // 8 hours
    private int sessionHardTimeoutSeconds = 86400;   // 24 hours
    private String sessionCookieName = "webauthn-proxy-session";
    private String userCookieName = "webauthn-proxy-username";
    private String usernameRegex = "^.+$";
    private boolean cookieSecure = false;
    private String cookieDomain = "";

    /** Optional CIDR networks for the /webauthn/verify 2FA endpoint. */
    private Map<String, List<String>> cidrNetworks = new HashMap<>();

    // --- Getters & Setters ---

    public String getRpDisplayName() { return rpDisplayName; }
    public void setRpDisplayName(String rpDisplayName) { this.rpDisplayName = rpDisplayName; }

    public String getRpId() { return rpId; }
    public void setRpId(String rpId) { this.rpId = rpId; }

    public List<String> getRpOrigins() { return rpOrigins; }
    public void setRpOrigins(List<String> rpOrigins) { this.rpOrigins = rpOrigins; }

    public boolean isTestMode() { return testMode; }
    public void setTestMode(boolean testMode) { this.testMode = testMode; }

    public int getSessionSoftTimeoutSeconds() { return sessionSoftTimeoutSeconds; }
    public void setSessionSoftTimeoutSeconds(int v) { this.sessionSoftTimeoutSeconds = v; }

    public int getSessionHardTimeoutSeconds() { return sessionHardTimeoutSeconds; }
    public void setSessionHardTimeoutSeconds(int v) { this.sessionHardTimeoutSeconds = v; }

    public String getSessionCookieName() { return sessionCookieName; }
    public void setSessionCookieName(String v) { this.sessionCookieName = v; }

    public String getUserCookieName() { return userCookieName; }
    public void setUserCookieName(String v) { this.userCookieName = v; }

    public String getUsernameRegex() { return usernameRegex; }
    public void setUsernameRegex(String v) { this.usernameRegex = v; }

    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean v) { this.cookieSecure = v; }

    public String getCookieDomain() { return cookieDomain; }
    public void setCookieDomain(String v) { this.cookieDomain = v; }

    public Map<String, List<String>> getCidrNetworks() { return cidrNetworks; }
    public void setCidrNetworks(Map<String, List<String>> v) { this.cidrNetworks = v; }
}
