package com.example.passkeyproxy.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;

@Configuration
public class AppConfig {

    private static final Logger log = LoggerFactory.getLogger(AppConfig.class);

    @Value("${proxy.config-path:./config}")
    private String configPath;

    @Bean
    public ProxySettings proxySettings() throws IOException {
        Path configFile = Path.of(configPath, "config.yml");
        log.info("Loading proxy config from {}", configFile.toAbsolutePath());
        Yaml yaml = new Yaml(new Constructor(ProxySettings.class, new LoaderOptions()));
        try (FileInputStream fis = new FileInputStream(configFile.toFile())) {
            ProxySettings settings = yaml.load(fis);
            if (settings == null) {
                settings = new ProxySettings();
            }
            validate(settings);
            printEffectiveConfig(settings);
            return settings;
        }
    }

    @Bean
    public CredentialsFileConfig credentialsFileConfig() throws IOException {
        Path credFile = Path.of(configPath, "credentials.yml");
        log.info("Loading credentials from {}", credFile.toAbsolutePath());
        Yaml yaml = new Yaml(new Constructor(CredentialsFileConfig.class, new LoaderOptions()));
        try (FileInputStream fis = new FileInputStream(credFile.toFile())) {
            CredentialsFileConfig cfg = yaml.load(fis);
            if (cfg == null) {
                cfg = new CredentialsFileConfig();
            }
            return cfg;
        }
    }

    /** Non-strict manager: skips attestation statement verification (suitable for passkeys). */
    @Bean
    public WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }

    /** webauthn4j's ObjectConverter provides CBOR + JSON converters with WebAuthn serializers. */
    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    private void validate(ProxySettings s) {
        if (s.getSessionSoftTimeoutSeconds() < 1) {
            throw new IllegalStateException("sessionSoftTimeoutSeconds must be > 0");
        }
        if (s.getSessionHardTimeoutSeconds() < 1) {
            throw new IllegalStateException("sessionHardTimeoutSeconds must be > 0");
        }
        if (s.getSessionHardTimeoutSeconds() < s.getSessionSoftTimeoutSeconds()) {
            throw new IllegalStateException("sessionHardTimeoutSeconds must be >= sessionSoftTimeoutSeconds");
        }
    }

    private void printEffectiveConfig(ProxySettings s) {
        log.info("=== Proxy Configuration ===");
        log.info("  RP Display Name : {}", s.getRpDisplayName());
        log.info("  RP ID           : {}", s.getRpId());
        log.info("  RP Origins      : {}", s.getRpOrigins());
        log.info("  Test Mode       : {}", s.isTestMode());
        log.info("  Soft Timeout    : {}s", s.getSessionSoftTimeoutSeconds());
        log.info("  Hard Timeout    : {}s", s.getSessionHardTimeoutSeconds());
        log.info("  Cookie Secure   : {}", s.isCookieSecure());
        log.info("  Cookie Domain   : {}", s.getCookieDomain());
        if (s.isTestMode()) {
            log.warn("=== WARNING: Test Mode is enabled! Do not use in production! ===");
        }
    }
}
