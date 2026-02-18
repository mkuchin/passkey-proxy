```
  
  Project structure                                                                                                                                                                                              
                                                                                                                                                                                                                 
  passkey-proxy/                                                                                                                                                                                                 
  ├── build.gradle / settings.gradle                                                                                                                                                                             
  ├── config/                                                                                                                                                                                                    
  │   ├── config.yml          ← edit this to configure the proxy                                                                                                                                                 
  │   └── credentials.yml     ← paste user credentials here after registration                                                                                                                                   
  └── src/main/                                                                                                                                                                                                  
      ├── resources/                                                                                                                                                                                             
      │   ├── application.yml                                                                                                                                                                                    
      │   └── static/         ← login.html, register.html, authenticated.html                                                                                                                                    
      └── java/…/                                                                                                                                                                                                
          ├── config/         AppConfig, ProxySettings, CredentialsFileConfig
          ├── model/          StoredUser, StoredCredential, WebAuthnCredentialRecord
          ├── service/        WebAuthnService, UserStore
          ├── controller/     WebAuthnController  (all 10 endpoints)
          └── util/           RequestUtil


  Endpoints (identical to Go version)

  ┌────────┬─────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────────┐
  │ Method │                        Path                         │                            Purpose                            │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/auth                                      │ nginx auth_request target — 200 + X-Authenticated-User header │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/login                                     │ Serves login page or redirects if already authed              │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/login/get_credential_request_options      │ Step 1 login                                                  │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ POST   │ /webauthn/login/process_login_assertion             │ Step 2 login                                                  │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/register                                  │ Serves register page                                          │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/register/get_credential_creation_options  │ Step 1 registration                                           │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ POST   │ /webauthn/register/process_registration_attestation │ Step 2 registration                                           │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/verify                                    │ One-time 2FA check (IP exact or CIDR match)                   │
  ├────────┼─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
  │ GET    │ /webauthn/logout                                    │ Invalidates session                                           │
  └────────┴─────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────────┘

  Running

  ./gradlew bootRun
  # or build a fat jar:
  ./gradlew bootJar
  java -jar build/libs/passkey-proxy-1.0.0-SNAPSHOT.jar


  Registration workflow (same as Go version)

  1. User visits /webauthn/register, registers their passkey
  2. Server logs a YAML line like alice: '{"name":"alice","userId":"...","credentials":[...]}'
  3. Admin pastes that line under users: in config/credentials.yml and restarts
  4. With testMode: true in config.yml users are auto-activated (dev only)

```
