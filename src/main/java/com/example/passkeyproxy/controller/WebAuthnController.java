package com.example.passkeyproxy.controller;

import com.example.passkeyproxy.config.ProxySettings;
import com.example.passkeyproxy.model.StoredCredential;
import com.example.passkeyproxy.model.StoredUser;
import com.example.passkeyproxy.model.WebAuthnCredentialRecord;
import com.example.passkeyproxy.service.UserStore;
import com.example.passkeyproxy.service.WebAuthnService;
import com.example.passkeyproxy.util.RequestUtil;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * All WebAuthn proxy endpoints, mirroring the Go webauthn_proxy project.
 *
 * <h2>Endpoints</h2>
 * <ul>
 *   <li>GET  /                                              → redirect to /webauthn/login</li>
 *   <li>GET  /webauthn/login                               → login page or authenticated page</li>
 *   <li>GET  /webauthn/login/get_credential_request_options</li>
 *   <li>POST /webauthn/login/process_login_assertion</li>
 *   <li>GET  /webauthn/register                            → registration page</li>
 *   <li>GET  /webauthn/register/get_credential_creation_options</li>
 *   <li>POST /webauthn/register/process_registration_attestation</li>
 *   <li>GET  /webauthn/auth                               → session check (nginx auth_request)</li>
 *   <li>GET  /webauthn/verify                             → one-time 2FA verification</li>
 *   <li>GET  /webauthn/logout</li>
 * </ul>
 */
@RestController
public class WebAuthnController {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnController.class);

    static final String AUTHENTICATED_USER_HEADER = "X-Authenticated-User";
    private static final String SESSION_KEY_AUTHENTICATED = "authenticated";
    private static final String SESSION_KEY_USER = "authenticated_user";
    private static final String SESSION_KEY_TIME = "authenticated_time";
    private static final String SESSION_KEY_IP = "authenticated_ip";
    private static final String SESSION_KEY_REG_CHALLENGE = "registration_challenge";
    private static final String SESSION_KEY_AUTH_CHALLENGE = "authentication_challenge";

    /** Holds recent logins for the /webauthn/verify 2FA endpoint (username → login info). */
    private final Map<String, LoginVerification> loginVerifications = new ConcurrentHashMap<>();

    private final ProxySettings settings;
    private final WebAuthnService webAuthnService;
    private final UserStore userStore;

    public WebAuthnController(ProxySettings settings,
                              WebAuthnService webAuthnService,
                              UserStore userStore) {
        this.settings = settings;
        this.webAuthnService = webAuthnService;
        this.userStore = userStore;
    }

    // =========================================================================
    // Root redirect
    // =========================================================================

    @GetMapping("/")
    public ResponseEntity<Void> index() {
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .header("Location", "/webauthn/login")
                .build();
    }

    // =========================================================================
    // Auth check  (nginx auth_request target)
    // =========================================================================

    /**
     * GET /webauthn/auth — returns 200 + X-Authenticated-User if the session is valid.
     * Used as an nginx {@code auth_request} backend.
     */
    @GetMapping("/webauthn/auth")
    public ResponseEntity<Map<String, Object>> handleAuth(HttpSession session,
                                                          HttpServletRequest request,
                                                          HttpServletResponse response) {
        Boolean authenticated = (Boolean) session.getAttribute(SESSION_KEY_AUTHENTICATED);
        if (!Boolean.TRUE.equals(authenticated)) {
            return unauthorized("Unauthenticated");
        }

        String username = (String) session.getAttribute(SESSION_KEY_USER);
        Long authTime = (Long) session.getAttribute(SESSION_KEY_TIME);
        String authIp = (String) session.getAttribute(SESSION_KEY_IP);

        // Hard timeout check
        if (authTime == null || Instant.now().getEpochSecond() - authTime >= settings.getSessionHardTimeoutSeconds()) {
            log.debug("Session hard timeout for user {}", username);
            session.invalidate();
            return unauthorized("Session expired");
        }

        // IP mismatch → force re-login
        String currentIp = RequestUtil.getClientIp(request);
        if (!currentIp.equals(authIp)) {
            log.debug("IP mismatch for user {}: was {}, now {}", username, authIp, currentIp);
            session.invalidate();
            return unauthorized("IP changed");
        }

        // Touching the session resets the inactivity (soft) timeout automatically.
        return ResponseEntity.ok()
                .header(AUTHENTICATED_USER_HEADER, username)
                .body(error("OK"));
    }

    // =========================================================================
    // Login
    // =========================================================================

    /**
     * GET /webauthn/login — serves login.html for unauthenticated users; redirects
     * authenticated users (or to redirect_url if provided).
     */
    @GetMapping(value = "/webauthn/login", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Void> handleLogin(HttpSession session,
                                            @RequestParam(required = false) String redirect_url,
                                            HttpServletResponse response) {
        Boolean authenticated = (Boolean) session.getAttribute(SESSION_KEY_AUTHENTICATED);
        if (Boolean.TRUE.equals(authenticated)) {
            String dest = (redirect_url != null && !redirect_url.isBlank())
                    ? redirect_url
                    : "/webauthn/static/authenticated.html";
            return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                    .header("Location", dest)
                    .build();
        }
        // Serve login.html (Spring serves it from /webauthn/static/login.html)
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .header("Location", "/webauthn/static/login.html")
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .build();
    }

    /**
     * GET /webauthn/login/get_credential_request_options
     * Step 1 of login: returns PublicKeyCredentialRequestOptions JSON.
     */
    @GetMapping("/webauthn/login/get_credential_request_options")
    public ResponseEntity<Map<String, Object>> getCredentialRequestOptions(
            @RequestParam String username,
            HttpSession session) {

        if (!isValidUsername(username)) {
            log.warn("Invalid username format: {}", username);
            return ResponseEntity.badRequest().body(error("Invalid username"));
        }

        StoredUser user = userStore.getUser(username);
        if (user == null) {
            log.warn("Login attempt for unknown user: {}", username);
            return ResponseEntity.badRequest().body(error("User not found"));
        }

        Challenge challenge = webAuthnService.generateChallenge();
        session.setAttribute(SESSION_KEY_AUTH_CHALLENGE,
                Base64.getEncoder().encodeToString(challenge.getValue()));

        List<Map<String, Object>> allowCredentials = webAuthnService.buildCredentialDescriptors(user);

        Map<String, Object> publicKey = new LinkedHashMap<>();
        publicKey.put("challenge",
                Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue()));
        publicKey.put("timeout", 60000);
        publicKey.put("rpId", settings.getRpId());
        publicKey.put("allowCredentials", allowCredentials);
        publicKey.put("userVerification", "preferred");

        return ResponseEntity.ok(Map.of("publicKey", publicKey));
    }

    /**
     * POST /webauthn/login/process_login_assertion
     * Step 2 of login: verifies the credential assertion.
     */
    @PostMapping("/webauthn/login/process_login_assertion")
    public ResponseEntity<Map<String, Object>> processLoginAssertion(
            @RequestParam String username,
            @RequestBody String authenticationResponseJson,
            HttpSession session,
            HttpServletRequest request,
            HttpServletResponse response) {

        if (!isValidUsername(username)) {
            return ResponseEntity.badRequest().body(error("Invalid username"));
        }

        StoredUser user = userStore.getUser(username);
        if (user == null) {
            log.warn("Login assertion for unknown user: {}", username);
            return ResponseEntity.badRequest().body(error("User not found"));
        }

        String challengeB64 = (String) session.getAttribute(SESSION_KEY_AUTH_CHALLENGE);
        if (challengeB64 == null) {
            log.warn("No authentication challenge in session for user: {}", username);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("No challenge in session"));
        }
        session.removeAttribute(SESSION_KEY_AUTH_CHALLENGE);

        Challenge challenge = new DefaultChallenge(Base64.getDecoder().decode(challengeB64));
        String origin = RequestUtil.getOrigin(request);

        // Find the credential being used
        AuthenticationData authData;
        try {
            // Parse first to get the credential ID, then look up the stored credential
            authData = com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager()
                    .parseAuthenticationResponseJSON(authenticationResponseJson);
        } catch (Exception e) {
            log.error("Failed to parse authentication response for user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error("Unable to login"));
        }

        byte[] credentialId = authData.getCredentialId();
        StoredCredential storedCredential = user.findCredential(credentialId);
        if (storedCredential == null) {
            log.warn("Credential not found for user {} with id {}",
                    username, Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId));
            return ResponseEntity.badRequest().body(error("Credential not registered"));
        }

        WebAuthnCredentialRecord credentialRecord = webAuthnService.toCredentialRecord(storedCredential);

        AuthenticationData verified;
        try {
            verified = webAuthnService.verifyAuthentication(
                    authenticationResponseJson, challenge, origin, credentialRecord);
        } catch (Exception e) {
            log.error("Authentication verification failed for user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error("Unable to login"));
        }

        // Check for cloned authenticator (sign counter regression)
        long newCounter = verified.getAuthenticatorData().getSignCount();
        if (newCounter != 0 && newCounter <= storedCredential.getCounter()) {
            log.error("Clone warning for user {}: stored counter={}, received counter={}",
                    username, storedCredential.getCounter(), newCounter);
            return ResponseEntity.badRequest().body(error("Cloned authenticator detected"));
        }

        // Update sign counter
        storedCredential.setCounter(newCounter);

        // Record login for /webauthn/verify 2FA endpoint
        String clientIp = RequestUtil.getClientIp(request);
        loginVerifications.put(username, new LoginVerification(clientIp, Instant.now()));

        // Set session as authenticated
        session.setAttribute(SESSION_KEY_AUTHENTICATED, true);
        session.setAttribute(SESSION_KEY_USER, username);
        session.setAttribute(SESSION_KEY_TIME, Instant.now().getEpochSecond());
        session.setAttribute(SESSION_KEY_IP, clientIp);

        // Set a plain username cookie for pre-filling the login form on next visit
        Cookie userCookie = new Cookie(settings.getUserCookieName(), username);
        userCookie.setPath("/");
        userCookie.setMaxAge(365 * 24 * 3600); // 1 year
        userCookie.setSecure(settings.isCookieSecure());
        userCookie.setHttpOnly(false); // Readable by JS to pre-fill the login form
        if (!settings.getCookieDomain().isBlank()) {
            userCookie.setDomain(settings.getCookieDomain());
        }
        response.addCookie(userCookie);

        log.info("User {} authenticated successfully from {}", username, clientIp);
        return ResponseEntity.ok(error("Authentication Successful"));
    }

    // =========================================================================
    // Registration
    // =========================================================================

    /** GET /webauthn/register — served as a static file by Spring. */
    @GetMapping("/webauthn/register")
    public ResponseEntity<Void> handleRegister() {
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .header("Location", "/webauthn/static/register.html")
                .build();
    }

    /**
     * GET /webauthn/register/get_credential_creation_options
     * Step 1 of registration: returns PublicKeyCredentialCreationOptions JSON.
     */
    @GetMapping("/webauthn/register/get_credential_creation_options")
    public ResponseEntity<Map<String, Object>> getCredentialCreationOptions(
            @RequestParam String username,
            HttpSession session) {

        if (!isValidUsername(username)) {
            return ResponseEntity.badRequest().body(error("Invalid username"));
        }

        StoredUser user = userStore.getOrCreateForRegistration(username);

        Challenge challenge = webAuthnService.generateChallenge();
        session.setAttribute(SESSION_KEY_REG_CHALLENGE,
                Base64.getEncoder().encodeToString(challenge.getValue()));

        List<Map<String, Object>> excludeCredentials = webAuthnService.buildCredentialDescriptors(user);

        Map<String, Object> rp = Map.of("id", settings.getRpId(), "name", settings.getRpDisplayName());

        Map<String, Object> userMap = new LinkedHashMap<>();
        userMap.put("id", user.getUserId());
        userMap.put("name", username);
        userMap.put("displayName", username);

        List<Map<String, Object>> pubKeyCredParams = List.of(
                Map.of("type", "public-key", "alg", -7),   // ES256
                Map.of("type", "public-key", "alg", -257)  // RS256
        );

        Map<String, Object> authenticatorSelection = new LinkedHashMap<>();
        authenticatorSelection.put("userVerification", "preferred");
        authenticatorSelection.put("residentKey", "preferred");

        Map<String, Object> publicKey = new LinkedHashMap<>();
        publicKey.put("rp", rp);
        publicKey.put("user", userMap);
        publicKey.put("challenge",
                Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue()));
        publicKey.put("pubKeyCredParams", pubKeyCredParams);
        publicKey.put("timeout", 60000);
        publicKey.put("attestation", "none");
        publicKey.put("authenticatorSelection", authenticatorSelection);
        if (!excludeCredentials.isEmpty()) {
            publicKey.put("excludeCredentials", excludeCredentials);
        }

        return ResponseEntity.ok(Map.of("publicKey", publicKey));
    }

    /**
     * POST /webauthn/register/process_registration_attestation
     * Step 2 of registration: verifies the new credential.
     */
    @PostMapping("/webauthn/register/process_registration_attestation")
    public ResponseEntity<Map<String, Object>> processRegistrationAttestation(
            @RequestParam String username,
            @RequestBody String registrationResponseJson,
            HttpSession session,
            HttpServletRequest request) {

        if (!isValidUsername(username)) {
            return ResponseEntity.badRequest().body(error("Invalid username"));
        }

        StoredUser user = userStore.getUser(username);
        if (user == null) {
            user = userStore.getPendingRegistration(username);
        }
        if (user == null) {
            log.error("User {} skipped get_credential_creation_options", username);
            return ResponseEntity.badRequest().body(error("Registration flow error"));
        }

        String challengeB64 = (String) session.getAttribute(SESSION_KEY_REG_CHALLENGE);
        if (challengeB64 == null) {
            return ResponseEntity.badRequest().body(error("No challenge in session"));
        }
        session.removeAttribute(SESSION_KEY_REG_CHALLENGE);

        Challenge challenge = new DefaultChallenge(Base64.getDecoder().decode(challengeB64));
        String origin = RequestUtil.getOrigin(request);

        RegistrationData registrationData;
        try {
            registrationData = webAuthnService.verifyRegistration(
                    registrationResponseJson, challenge, origin);
        } catch (Exception e) {
            log.error("Registration verification failed for user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(error("Error during registration"));
        }

        byte[] credentialId = registrationData.getAttestationObject()
                .getAuthenticatorData().getAttestedCredentialData().getCredentialId();

        if (userStore.isCredentialIdTaken(credentialId)) {
            log.error("Credential already registered (duplicate) for user {}", username);
            return ResponseEntity.badRequest().body(error("Credential already registered"));
        }

        StoredCredential storedCredential = webAuthnService.toStoredCredential(registrationData);
        user.addCredential(storedCredential);

        if (settings.isTestMode()) {
            userStore.activateRegistration(username);
            log.info("Test mode: auto-activated user {}", username);
        }

        String marshaledUser;
        try {
            marshaledUser = userStore.marshalUser(user);
        } catch (Exception e) {
            log.error("Failed to marshal user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(error("Error during registration"));
        }

        String credEntry = "%s: '%s'".formatted(username, marshaledUser);
        log.info("New registration for user {}: {}", username, credEntry);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("message", "Registration Successful. Share the credential below with your administrator.");
        result.put("data", credEntry);
        return ResponseEntity.ok(result);
    }

    // =========================================================================
    // Logout
    // =========================================================================

    @GetMapping("/webauthn/logout")
    public ResponseEntity<Void> handleLogout(HttpSession session) {
        try {
            session.invalidate();
        } catch (Exception ignored) {}
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .header("Location", "/webauthn/login")
                .build();
    }

    // =========================================================================
    // One-time 2FA verification  (/webauthn/verify)
    // =========================================================================

    /**
     * GET /webauthn/verify?username=alice&amp;ip=1.2.3.4
     *
     * <p>Checks whether the user has authenticated within the last 5 minutes from an IP
     * matching the given IP (exact or CIDR). Useful as a lightweight 2FA step for
     * downstream services.
     */
    @GetMapping("/webauthn/verify")
    public ResponseEntity<Map<String, Object>> handleVerify(
            @RequestParam String username,
            @RequestParam String ip) {

        LoginVerification verification = loginVerifications.get(username);
        if (verification == null) {
            return unauthorized("No recent login found");
        }

        // Must be within the last 5 minutes
        if (verification.loginTime().plusSeconds(300).isBefore(Instant.now())) {
            loginVerifications.remove(username);
            return unauthorized("Login verification expired");
        }

        String webAuthnIp = verification.ipAddr();

        // Exact IP match
        if (webAuthnIp.equals(ip)) {
            loginVerifications.remove(username);
            log.info("User {} verified with exact IP match from {}", username, ip);
            return ResponseEntity.ok(Map.of("status", "OK", "match_method", "exact"));
        }

        // CIDR match
        for (Map.Entry<String, List<String>> network : settings.getCidrNetworks().entrySet()) {
            String networkName = network.getKey();
            for (String cidr : network.getValue()) {
                if (bothInCidr(webAuthnIp, ip, cidr)) {
                    loginVerifications.remove(username);
                    log.info("User {} verified via CIDR match: webAuthnIp={}, userIp={}, network={}, cidr={}",
                            username, webAuthnIp, ip, networkName, cidr);
                    return ResponseEntity.ok(Map.of(
                            "status", "OK",
                            "match_method", "cidr",
                            "webauthn_ip", webAuthnIp,
                            "user_ip", ip,
                            "network_name", networkName,
                            "matched_cidr", cidr));
                }
            }
        }

        log.warn("User {} failed verification: auth IP={}, validating IP={}", username, webAuthnIp, ip);
        return unauthorized("IP verification failed");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private boolean isValidUsername(String username) {
        if (username == null || username.isBlank()) return false;
        return Pattern.matches(settings.getUsernameRegex(), username);
    }

    private Map<String, Object> error(String msg) {
        return Map.of("message", msg);
    }

    private ResponseEntity<Map<String, Object>> unauthorized(String msg) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error(msg));
    }

    private boolean bothInCidr(String ip1, String ip2, String cidr) {
        try {
            String[] parts = cidr.split("/");
            InetAddress network = InetAddress.getByName(parts[0]);
            int prefixLen = Integer.parseInt(parts[1]);
            byte[] networkBytes = network.getAddress();
            byte[] ip1Bytes = InetAddress.getByName(ip1).getAddress();
            byte[] ip2Bytes = InetAddress.getByName(ip2).getAddress();
            if (networkBytes.length != ip1Bytes.length || networkBytes.length != ip2Bytes.length) {
                return false;
            }
            int fullBytes = prefixLen / 8;
            int remainingBits = prefixLen % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (ip1Bytes[i] != networkBytes[i] || ip2Bytes[i] != networkBytes[i]) return false;
            }
            if (remainingBits > 0 && fullBytes < networkBytes.length) {
                int mask = 0xFF << (8 - remainingBits);
                return (ip1Bytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
                        && (ip2Bytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
            }
            return true;
        } catch (Exception e) {
            log.warn("Invalid CIDR {}: {}", cidr, e.getMessage());
            return false;
        }
    }

    // =========================================================================
    // Inner types
    // =========================================================================

    private record LoginVerification(String ipAddr, Instant loginTime) {}
}
