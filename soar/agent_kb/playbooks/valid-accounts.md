# Playbook: Valid-account / token abuse

**Applies to:** login/session activity using a legitimately-issued credential or token
obtained through a prior compromise — e.g. the admin JWT obtained via the Juice Shop
SQLi auth-bypass (see `sqli-juiceshop.md`) being used to access admin-only endpoints
afterward. MITRE **T1078** (Valid Accounts).

## Why this is different from every other playbook here
Every other technique in this KB looks suspicious on its face (a scan, a SQLi payload,
a credential dump). T1078 activity looks completely normal — a valid login, a valid
token used correctly — because that is the point of the technique. The signal is not
"is this action malicious" but **"was this credential/token legitimately obtained"**.

## Triage steps
1. Trace how the account/token was obtained. Was there a preceding exploitation alert
   on the same source (e.g. a SQLi auth-bypass, a successful brute-force) shortly
   before this activity? `search_past_cases(<ip or hostname>)` and
   `search_elasticsearch` for a preceding compromise are the primary signal here.
2. Check whether the actions taken with the account are consistent with its normal
   use, or whether they look like followup abuse (admin-only endpoints accessed
   immediately after an unusual login, data exfiltration patterns, account changes).
3. If there is NO preceding compromise indicator and the login/token use looks
   ordinary, this is very likely legitimate — do not manufacture suspicion.

## Decision guidance
- A preceding exploitation/auth-bypass alert on the same source, followed by
  privileged actions with the resulting credential → **malicious**, severity
  **critical** (this is post-compromise account abuse), technique T1078, confidence
  ~0.85.
- No preceding compromise indicator, ordinary-looking account activity → **benign**,
  do not flag speculatively.

## Response
- Containment depends entirely on whether the SOURCE performing the abuse is
  external/blockable — the guard's normal rules apply. But the deeper remediation
  (revoke the compromised token/credential) is a host/application action outside this
  project's automated network-containment scope — always escalate a confirmed case to
  a human.
