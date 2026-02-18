package com.example.passkeyproxy.model;

import com.webauthn4j.credential.CoreCredentialRecordImpl;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.data.client.CollectedClientData;

import java.util.Set;

/**
 * A {@link CredentialRecord} implementation used when reconstructing a stored credential
 * for authentication verification. Extends {@link CoreCredentialRecordImpl} which provides
 * the counter, attested credential data, and UV/backup flag storage.
 */
public class WebAuthnCredentialRecord extends CoreCredentialRecordImpl implements CredentialRecord {

    private final Set<AuthenticatorTransport> transports;

    public WebAuthnCredentialRecord(
            AttestedCredentialData attestedCredentialData,
            long counter,
            Boolean uvInitialized,
            Boolean backupEligible,
            Boolean backedUp,
            Set<AuthenticatorTransport> transports) {
        // Use the CoreCredentialRecordImpl constructor that takes individual fields.
        // attestationStatement = null (not needed for authentication)
        // authenticatorExtensions = null
        super(null, uvInitialized, backupEligible, backedUp, counter, attestedCredentialData, null);
        this.transports = transports;
    }

    @Override
    public CollectedClientData getClientData() {
        return null;
    }

    @Override
    public AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return null;
    }

    @Override
    public Set<AuthenticatorTransport> getTransports() {
        return transports;
    }
}
