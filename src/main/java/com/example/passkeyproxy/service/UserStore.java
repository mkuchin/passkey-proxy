package com.example.passkeyproxy.service;

import com.example.passkeyproxy.config.CredentialsFileConfig;
import com.example.passkeyproxy.model.StoredUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.FileWriter;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory user store backed by credentials.yml.
 *
 * <p>Mirrors the Go version's {@code users} and {@code registrations} maps:
 * <ul>
 *   <li>{@code users} — persisted, loaded from file at startup</li>
 *   <li>{@code registrations} — temporary, holds credentials pending admin approval</li>
 * </ul>
 */
@Service
public class UserStore {

    private static final Logger log = LoggerFactory.getLogger(UserStore.class);

    @Value("${proxy.config-path:./config}")
    private String configPath;

    private final CredentialsFileConfig credentialsFileConfig;
    private final ObjectMapper objectMapper;

    /** Persisted users (loaded from credentials.yml). */
    private final Map<String, StoredUser> users = new ConcurrentHashMap<>();

    /** Pending registrations awaiting admin approval (in-memory only). */
    private final Map<String, StoredUser> registrations = new ConcurrentHashMap<>();

    public UserStore(CredentialsFileConfig credentialsFileConfig, ObjectMapper objectMapper) {
        this.credentialsFileConfig = credentialsFileConfig;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void load() {
        int count = 0;
        for (Map.Entry<String, String> entry : credentialsFileConfig.getUsers().entrySet()) {
            String username = entry.getKey();
            try {
                StoredUser user = objectMapper.readValue(entry.getValue(), StoredUser.class);
                if (!username.equals(user.getName())) {
                    throw new IllegalStateException(
                            "Username mismatch in credentials.yml: key='%s', user.name='%s'"
                                    .formatted(username, user.getName()));
                }
                users.put(username, user);
                count++;
            } catch (Exception e) {
                throw new RuntimeException("Failed to load credential for user '%s'".formatted(username), e);
            }
        }
        log.info("Loaded {} user credential(s) from credentials.yml", count);
    }

    /** Returns the active (persisted) user, or null. */
    public StoredUser getUser(String username) {
        return users.get(username);
    }

    /**
     * Returns the user from either the active store or the pending registrations map.
     * If not found in either, creates a new pending registration entry.
     */
    public StoredUser getOrCreateForRegistration(String username) {
        StoredUser user = users.get(username);
        if (user != null) return user;

        return registrations.computeIfAbsent(username, StoredUser::new);
    }

    /** Returns a pending registration user, or null. */
    public StoredUser getPendingRegistration(String username) {
        return registrations.get(username);
    }

    /**
     * Activates a pending registration (test mode only).
     * Moves the user from registrations → users.
     */
    public void activateRegistration(String username) {
        StoredUser user = registrations.remove(username);
        if (user != null) {
            users.put(username, user);
        }
    }

    /**
     * Serializes a {@link StoredUser} to the JSON string format used in credentials.yml.
     */
    public String marshalUser(StoredUser user) throws Exception {
        return objectMapper.writeValueAsString(user);
    }

    /**
     * Checks whether the given credential ID is already registered to any user or pending
     * registrant (to prevent sharing credentials across accounts).
     */
    public boolean isCredentialIdTaken(byte[] credentialId) {
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        for (StoredUser u : users.values()) {
            if (u.getCredentials().stream().anyMatch(c -> b64.equals(c.getCredentialId()))) {
                return true;
            }
        }
        for (StoredUser u : registrations.values()) {
            if (u.getCredentials().stream().anyMatch(c -> b64.equals(c.getCredentialId()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds a persisted user by credential ID (for usernameless/discoverable-credential login).
     */
    public StoredUser findUserByCredentialId(byte[] credentialId) {
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        return users.values().stream()
                .filter(u -> u.getCredentials().stream().anyMatch(c -> b64.equals(c.getCredentialId())))
                .findFirst()
                .orElse(null);
    }

    /**
     * Persists a user to credentials.yml and activates them in the in-memory store.
     * Replaces the manual admin-approval workflow.
     */
    public void persistUser(String username, StoredUser user) throws Exception {
        users.put(username, user);
        registrations.remove(username);

        // Serialize all current users and write to credentials.yml
        Map<String, String> serializedUsers = new LinkedHashMap<>();
        for (Map.Entry<String, StoredUser> entry : users.entrySet()) {
            serializedUsers.put(entry.getKey(), objectMapper.writeValueAsString(entry.getValue()));
        }

        Map<String, Object> rawConfig = new LinkedHashMap<>();
        rawConfig.put("users", serializedUsers);

        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Yaml yaml = new Yaml(opts);

        Path credFile = Path.of(configPath, "credentials.yml");
        try (FileWriter writer = new FileWriter(credFile.toFile())) {
            yaml.dump(rawConfig, writer);
        }
        log.info("Persisted user {} to credentials.yml", username);
    }
}
