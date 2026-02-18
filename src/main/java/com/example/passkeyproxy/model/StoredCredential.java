package com.example.passkeyproxy.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Serializable form of a WebAuthn credential stored in credentials.yml.
 *
 * <p>The COSE public key is stored as a Base64-encoded CBOR byte array so that
 * it can be round-tripped through webauthn4j's CborConverter.
 */
public class StoredCredential {

    /** Base64url-encoded credential ID. */
    private String credentialId;

    /** UUID string representation of the authenticator AAGUID. */
    private String aaguid;

    /**
     * Base64-encoded CBOR-encoded COSE public key.
     * Reconstructed via {@code ObjectConverter.getCborConverter().readValue(bytes, COSEKey.class)}.
     */
    private String coseKey;

    /** Signature counter (monotonically increasing, 0 if authenticator doesn't use it). */
    private long counter;

    private Boolean uvInitialized;
    private Boolean backupEligible;
    private Boolean backedUp;

    /** Transport hints, e.g. ["internal"], ["usb"], ["nfc", "ble"]. */
    private List<String> transports = new ArrayList<>();

    // --- Getters & Setters ---

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String v) { this.credentialId = v; }

    public String getAaguid() { return aaguid; }
    public void setAaguid(String v) { this.aaguid = v; }

    public String getCoseKey() { return coseKey; }
    public void setCoseKey(String v) { this.coseKey = v; }

    public long getCounter() { return counter; }
    public void setCounter(long v) { this.counter = v; }

    public Boolean getUvInitialized() { return uvInitialized; }
    public void setUvInitialized(Boolean v) { this.uvInitialized = v; }

    public Boolean getBackupEligible() { return backupEligible; }
    public void setBackupEligible(Boolean v) { this.backupEligible = v; }

    public Boolean getBackedUp() { return backedUp; }
    public void setBackedUp(Boolean v) { this.backedUp = v; }

    public List<String> getTransports() { return transports; }
    public void setTransports(List<String> v) { this.transports = v != null ? v : new ArrayList<>(); }
}
