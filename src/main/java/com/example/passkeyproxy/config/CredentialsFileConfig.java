package com.example.passkeyproxy.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loaded from config/credentials.yml.
 *
 * <pre>
 * cookie_session_secrets:
 *   - "some-random-secret"
 * users:
 *   alice: '{"name":"alice","userId":"...","credentials":[...]}'
 * </pre>
 */
public class CredentialsFileConfig {

    private List<String> cookieSessionSecrets = new ArrayList<>();

    /** Maps username → JSON-serialized StoredUser */
    private Map<String, String> users = new HashMap<>();

    public List<String> getCookieSessionSecrets() { return cookieSessionSecrets; }
    public void setCookieSessionSecrets(List<String> v) { this.cookieSessionSecrets = v; }

    public Map<String, String> getUsers() { return users; }
    public void setUsers(Map<String, String> v) { this.users = v; }
}
