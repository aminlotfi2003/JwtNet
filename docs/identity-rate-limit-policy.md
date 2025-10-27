# Identity & Authentication Rate-Limit and Abuse-Mitigation Policy

This matrix defines mandatory rate-limiting, abuse-mitigation, and response behaviors for all identity and authentication endpoints. Unless stated otherwise, responses **MUST** remain uniform and never disclose account or email existence. Every endpoint returns the generic message:

> "Invalid credentials or rate limit exceeded."

Risk signals such as anonymous proxies, unusual geolocation, new devices, or low IP reputation halve thresholds, mandate MFA/CAPTCHA step-up, and increase all delays.

## Global Controls

- **Partitioning Dimensions:** Always partition counters on the keys specified for each endpoint. Apply additional composite keys when multiple partitions apply simultaneously.
- **Algorithms:** Implement the exact windowing algorithm defined per endpoint (Sliding Window, Fixed Window, Token Bucket, or composites).
- **Security Actions:** Escalate friction gradually: Tarpit (500–1500 ms) → CAPTCHA → Temporary soft-lock (15 m) → Token/challenge revocation. Never delete accounts for lockouts.
- **Disposable/High-Risk Sources:** Shadow-ban disposable email domains and score Autonomous System Numbers (ASNs); apply stricter limits to datacenter ranges.
- **Session Integrity:** Revoke refresh-token chains on replay or rotation violations. Enforce strict device/IP fingerprint verification.
- **Privacy:** All error responses remain generic. Avoid any hints of enumeration, success/failure states, or existence of emails/accounts/domains.

## Endpoint Policy Matrix

| Endpoint | Partition Keys | Algorithm | Baseline Thresholds | Security Actions | Error & Notes |
| --- | --- | --- | --- | --- | --- |
| **POST /register** | per-IP, per-ASN (datacenter), per-EmailDomain, per-Tenant | Sliding Window + Token Bucket (bucket=2) | per-IP: 5 / 1 h; per-ASN(datacenter): 3 / 1 h; per-EmailDomain/Tenant: 20 / 1 h | Warn + CAPTCHA challenge after 3 / 1 h per-IP; 429 when per-IP >5 or per-ASN >3; shadow-ban disposable domains via graylist | Uniform responses; never reveal whether email exists; maintain tenant-level isolation |
| **POST /login** | per-Account (normalized email), per-IP, per-Device (cookie/deviceId), per-Tenant | Composite: Sliding (per-Account) + Fixed (per-IP) | per-Account: 10 failed / 15 m (segment window=3); per-IP: 100 failed / 1 h; per-Device: 20 / 1 h | After 5 fails / 15 m per-Account → Tarpit 500–1500 ms; After 10 fails / 15 m per-Account → Soft-lock 15 m + CAPTCHA; per-IP >100 / 1 h → 429 or Step-Up CAPTCHA; High risk context halves thresholds and forces MFA/CAPTCHA | Generic error string at all times; prevents enumeration and supports adaptive risk |
| **POST /login/two-factor** | per-Challenge(flowId), per-Account, per-IP | Fixed Window | per-Challenge: 5 / 10 m; per-IP: 50 / 10 m | After 3 failures → Tarpit; After 5 / 10 m → 429, invalidate challenge, reissue with added friction; >2 push in 5 m → require in-app confirmation | Mitigates MFA push fatigue; responses remain generic |
| **POST /refresh** | per-Session(refreshTokenId chain), per-Account, per-ClientId, per-IP | Token Bucket | per-Session: 1 / 30 s (bucket=3); per-Account: 60 / 10 m | ≥3 uses in 60 s from same session → revoke chain + force full re-auth; Device/IP mismatch → Step-Up MFA/CAPTCHA; old token reuse → revoke chain | Enforce strict rotation; block replay attacks |
| **POST /logout** | per-Account, per-IP | Fixed Window | 30 / 5 m per partition | Exceeding threshold → 429 (bot/script suspicion) | Maintain low friction while preventing abuse |
| **POST /users/{id}/password/rotate** | per-Account(userId), per-IP | Sliding Window | Verify current password: 5 / 15 m; Rotate requests: 3 / 1 h | After 5 errors → 423 soft-lock 15 m + CAPTCHA; successful verification slowly eases backoff | Responses uniform; no leakage of password validity |
| **POST /forgot-password** | per-Account(email), per-IP, per-Tenant | Fixed Window | per-Account: 3 / 30 m (daily cap 5); per-IP: 20 / 1 h (daily cap 50) | Reaching per-Account limit → 429 + generic reply; per-IP limit → CAPTCHA or 429 | Anti-enumeration: identical success/failure messaging |
| **POST /forgot-password/verify** | per-ResetFlow(resetId/codeId), per-IP | Fixed Window | per-Flow: 5 / 10 m; per-IP: 50 / 10 m | After 3 errors → Tarpit; After 5 attempts → invalidate flow and reissue with extra friction | Prevents brute-force of reset codes |
| **POST /reset-password** | per-Account, per-ResetToken, per-IP | Sliding Window | per-ResetToken: 3 / 15 m; per-Account: 5 / 1 h | After 3 / 15 m → invalidate token & require new flow; suspicious multi-IP behavior → Step-Up MFA/CAPTCHA | Maintain reset integrity; generic responses |
| **POST /users/{id}/two-factor/email/generate** | per-Account(userId), per-IP | Fixed Window | 3 / 15 m, daily cap 10 | After 3 / 15 m → 429 + exponential backoff delay; apply stricter review during MFA enrollment | Protect against token flooding; uniform replies |
| **POST /users/{id}/two-factor/email/enable** | per-Account(userId), per-IP | Fixed Window | 5 verifications / 10 m | After 5 attempts → invalidate code; user must regenerate; add CAPTCHA if risk detected | Uniform non-disclosure; mitigates brute force |

## Global Enumeration & Privacy Behavior

- Every endpoint returns the exact same failure string: `"Invalid credentials or rate limit exceeded."`
- Success responses never reveal whether an email/account/domain exists before an authenticated context.
- Account lockouts are temporary and reversible (soft-lock); no account deletion is performed because of rate limits.
- Apply additional contextual risk evaluation (device rotation, IP velocity, ASN scoring) to adjust thresholds dynamically while preserving baseline policies.

## Expected Security Outcomes

- **Bot registration suppression:** Tight per-IP/ASN/domain limits and disposable domain shadow-bans contain automated sign-up waves.
- **Brute-force resistance:** Per-account sliding windows with tarpit delays and soft-locks slow down credential stuffing and password guessing.
- **2FA & token integrity:** Push fatigue is minimized via per-challenge ceilings and enforced in-app confirmation; refresh token replay is blocked via strict rotation and chain revocation.
- **Tenant-level fairness:** Per-tenant partitions and domain quotas prevent cross-tenant abuse and spam campaigns.
- **Privacy preservation:** Uniform responses and capped flows eliminate email/account enumeration vectors.