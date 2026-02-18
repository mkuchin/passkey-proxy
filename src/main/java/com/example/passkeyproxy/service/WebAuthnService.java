package com.example.passkeyproxy.service;

import com.example.passkeyproxy.config.ProxySettings;
import com.example.passkeyproxy.model.StoredCredential;
import com.example.passkeyproxy.model.StoredUser;
import com.example.passkeyproxy.model.WebAuthnCredentialRecord;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Wraps the webauthn4j {@link WebAuthnManager} with higher-level registration and
 * authentication operations, and handles serialization of credential records to/from
 * the {@link StoredCredential} persistence format.
 */
@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final ProxySettings settings;

    public WebAuthnService(WebAuthnManager webAuthnManager,
                           ObjectConverter objectConverter,
                           ProxySettings settings) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = objectConverter;
        this.settings = settings;
    }

    // -------------------------------------------------------------------------
    // Challenge generation
    // -------------------------------------------------------------------------

    public Challenge generateChallenge() {
        return new DefaultChallenge();
    }

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    /**
     * Parses and verifies a registration response JSON string (as produced by the browser's
     * {@code navigator.credentials.create()} and serialized via the WebAuthn JSON API).
     *
     * @param registrationResponseJson the JSON from the browser
     * @param challenge                the challenge stored in the session
     * @param origin                   the request origin (scheme + host)
     * @return verified {@link RegistrationData}
     */
    public RegistrationData verifyRegistration(String registrationResponseJson,
                                               Challenge challenge,
                                               String origin) {
        RegistrationData registrationData = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJson);

        ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                settings.getRpId(),
                challenge,
                null
        );

        List<PublicKeyCredentialParameters> pubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );

        RegistrationParameters params = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false,  // userVerificationRequired
                true    // userPresenceRequired
        );

        return webAuthnManager.verify(registrationData, params);
    }

    /**
     * Converts verified {@link RegistrationData} into a {@link StoredCredential} for persistence.
     */
    public StoredCredential toStoredCredential(RegistrationData registrationData) {
        AttestedCredentialData acd =
                registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();

        // Serialize COSE public key to CBOR bytes for storage
        byte[] coseKeyBytes = objectConverter.getCborConverter().writeValueAsBytes(acd.getCOSEKey());

        StoredCredential sc = new StoredCredential();
        sc.setCredentialId(
                Base64.getUrlEncoder().withoutPadding().encodeToString(acd.getCredentialId()));
        sc.setAaguid(
                acd.getAaguid().getValue() != null ? acd.getAaguid().getValue().toString() : "00000000-0000-0000-0000-000000000000");
        sc.setCoseKey(Base64.getEncoder().encodeToString(coseKeyBytes));
        sc.setCounter(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        sc.setUvInitialized(registrationData.getAttestationObject().getAuthenticatorData().isFlagUV());
        sc.setBackupEligible(registrationData.getAttestationObject().getAuthenticatorData().isFlagBE());
        sc.setBackedUp(registrationData.getAttestationObject().getAuthenticatorData().isFlagBS());

        if (registrationData.getTransports() != null) {
            sc.setTransports(registrationData.getTransports().stream()
                    .map(AuthenticatorTransport::getValue)
                    .collect(Collectors.toList()));
        }

        return sc;
    }

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    /**
     * Parses and verifies an authentication response JSON string.
     *
     * @param authenticationResponseJson the JSON from the browser
     * @param challenge                  the challenge stored in the session
     *     * @param origin                     the request origin
     * @param credentialRecord           the stored credential for the authenticating user
     * @return verified {@link AuthenticationData}
     */
    public AuthenticationData verifyAuthentication(String authenticationResponseJson,
                                                   Challenge challenge,
                                                   String origin,
                                                   CredentialRecord credentialRecord) {
        AuthenticationData authenticationData =
                webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJson);

        ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                settings.getRpId(),
                challenge,
                null
        );

        AuthenticationParameters params = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,   // allowCredentials: null = accept any registered credential
                false,  // userVerificationRequired
                true    // userPresenceRequired
        );

        return webAuthnManager.verify(authenticationData, params);
    }

    /**
     * Reconstructs a {@link CredentialRecord} from a {@link StoredCredential} for use
     * during authentication verification.
     */
    public WebAuthnCredentialRecord toCredentialRecord(StoredCredential sc) {
        UUID aaguidUuid;
        try {
            aaguidUuid = UUID.fromString(sc.getAaguid());
        } catch (IllegalArgumentException e) {
            aaguidUuid = UUID.fromString("00000000-0000-0000-0000-000000000000");
        }

        AAGUID aaguid = new AAGUID(aaguidUuid);
        byte[] credentialId = Base64.getUrlDecoder().decode(sc.getCredentialId());
        byte[] coseKeyBytes = Base64.getDecoder().decode(sc.getCoseKey());
        COSEKey coseKey = objectConverter.getCborConverter().readValue(coseKeyBytes, COSEKey.class);

        AttestedCredentialData acd = new AttestedCredentialData(aaguid, credentialId, coseKey);

        Set<AuthenticatorTransport> transports = sc.getTransports().stream()
                .map(AuthenticatorTransport::create)
                .collect(Collectors.toSet());

        return new WebAuthnCredentialRecord(
                acd,
                sc.getCounter(),
                sc.getUvInitialized(),
                sc.getBackupEligible(),
                sc.getBackedUp(),
                transports
        );
    }

    /**
     * Builds the list of credential descriptors (for {@code allowCredentials} in auth options
     * and {@code excludeCredentials} in registration options).
     */
    public List<Map<String, Object>> buildCredentialDescriptors(StoredUser user) {
        return user.getCredentials().stream()
                .map(c -> {
                    Map<String, Object> desc = new LinkedHashMap<>();
                    desc.put("type", "public-key");
                    desc.put("id", c.getCredentialId());
                    if (!c.getTransports().isEmpty()) {
                        desc.put("transports", c.getTransports());
                    }
                    return desc;
                })
                .collect(Collectors.toList());
    }
}
