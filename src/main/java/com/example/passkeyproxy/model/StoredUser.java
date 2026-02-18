package com.example.passkeyproxy.model;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Serializable user record stored as JSON in credentials.yml.
 */
public class StoredUser {

    /** Username (matches the credentials.yml key). */
    private String name;

    /**
     * Base64url-encoded random user ID (WebAuthn user.id).
     * Generated once on first registration, never changes.
     */
    private String userId;

    private List<StoredCredential> credentials = new ArrayList<>();

    public StoredUser() {}

    public StoredUser(String name) {
        this.name = name;
        // Generate a random 16-byte user ID
        byte[] idBytes = UUID.randomUUID().toString().replace("-", "").substring(0, 16).getBytes();
        this.userId = Base64.getUrlEncoder().withoutPadding().encodeToString(idBytes);
    }

    public byte[] getUserIdBytes() {
        return Base64.getUrlDecoder().decode(userId);
    }

    // --- Getters & Setters ---

    public String getName() { return name; }
    public void setName(String v) { this.name = v; }

    public String getUserId() { return userId; }
    public void setUserId(String v) { this.userId = v; }

    public List<StoredCredential> getCredentials() { return credentials; }
    public void setCredentials(List<StoredCredential> v) { this.credentials = v != null ? v : new ArrayList<>(); }

    public void addCredential(StoredCredential credential) {
        this.credentials.add(credential);
    }

    /** Returns the credential matching the given credential ID bytes, or null. */
    public StoredCredential findCredential(byte[] credentialId) {
        String target = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        return credentials.stream()
                .filter(c -> target.equals(c.getCredentialId()))
                .findFirst()
                .orElse(null);
    }
}
