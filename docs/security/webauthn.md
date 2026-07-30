# WebAuthn security model

CyberAudit uses WebAuthn as the phishing-resistant factor for authentication and
step-up. Challenges are random, single-use, expire after five minutes and are
bound in Redis to the tenant, user and purpose. Registration verifies the RP ID,
trusted HTTPS origin, user presence and (in production-like environments) user
verification. Only the credential ID, COSE public key, sign counter and
authenticator metadata are persisted.

Multiple credentials are supported. A counter rollback is treated as suspected
credential cloning and fails closed. Revocation requires an authenticated
administrator and is audited. Recovery must use another registered credential
or the documented, identity-verified administrative process; support personnel
cannot bypass WebAuthn.

Browser-authenticator and recovery exercises remain mandatory readiness
evidence. Unit tests alone do not satisfy that check.
