# Suspicious Login Incident Summary

**Project:** IAM Access Review & Suspicious Login Investigation (using synthetic data)
**Prepared by:** Malolan G.

## Summary

Between 02:14 and 02:25 on 2026-08-03, the account of Jack Turner (`U010`, Network Engineer, IT) 
recorded five consecutive failed login attempts from a single source IP, immediately followed by a
successful login from that same IP address eleven minutes later. The attempts to login to the same 
account several times before receiving a successful login from the same source is indicative of 
credential stuffing attacks or a brute-force attack that was successful against the target account. 
The account had admin-level access to Cloud Console and did not have MFA enabled on the account, 
which means that the attacker could simply enter the correct password for the account to gain access
with no further forms of security to stop them.


## Detection

The activity was surfaced using the SQL investigation queries built for this review
(`sql/investigation_queries.sql`):
- A `GROUP BY source_ip` / `HAVING` query identifying IPs with unusually high failed-login counts
  flagged IP `192.0.2.150` (5 failures).
- A follow-up query joining that IP list against successful logins (`status = 'SUCCESS'`) showed one
  successful login from `192.0.2.150`, tied to `U010`.
- Independently, the pandas script (`scripts/access_review.py`) flagged the same pattern by checking
  for successful logins from any IP that exceeded the failed-login threshold.

## Evidence

| Timestamp | User | Source IP | Status | Country |
|---|---|---|---|---|
| 2026-08-03 02:14:00 | jack.turner (U010) | 192.0.2.150 | FAILURE | United States |
| 2026-08-03 02:16:00 | jack.turner (U010) | 192.0.2.150 | FAILURE | United States |
| 2026-08-03 02:18:00 | jack.turner (U010) | 192.0.2.150 | FAILURE | United States |
| 2026-08-03 02:20:00 | jack.turner (U010) | 192.0.2.150 | FAILURE | United States |
| 2026-08-03 02:22:00 | jack.turner (U010) | 192.0.2.150 | FAILURE | United States |
| 2026-08-03 02:25:00 | jack.turner (U010) | 192.0.2.150 | **SUCCESS** | United States |

Five failed attempts at regular ~2-minute intervals, all from the same IP, followed by a successful
login from that same IP. This does not fall within the pattern of a user just mistyping their own password
(which typically self-corrects within 1-2 tries), and it occurred at 02:xx local time, well outside
business hours.

## Affected Account

- **User:** Jack Turner (`U010`)
- **Role:** Network Engineer, IT
- **Access held:** `Admin` on Cloud Console
- **MFA status:** Disabled, so no secondary factor was required for the successful login

## Suspicious Source

- **IP address:** `192.0.2.150`
- **Country (per login record):** United States
- **Behavior:** Sole use during this window was against `U010`'s account: five rapid failures then
  one success, rather than a broad sweep across many accounts (contrast with IP `203.0.113.77`
  elsewhere in the dataset, which generated 25 failures spread across many different accounts and
  never succeeded).

## Possible Impact

Because `U010` holds `Admin` access to Cloud Console, a successful unauthorized login would give an
attacker the ability to view or provision cloud infrastructure. Also, since MFA was not enabled, the 
attacker could log in to the system without encountering another layer of security. So, this presents 
a credible scenario for account takeovers.

## Recommended Containment

1. Force an immediate password reset on `U010` and invalidate any active sessions/tokens.
2. Temporarily suspend `U010`'s Cloud Console Admin access pending confirmation from the user that
   the 02:25 login was legitimate.
3. Review Cloud Console audit logs for any changes made during or shortly after the 02:25 session.
4. Block or rate-limit further authentication attempts from `192.0.2.150`.

## Longer-Term Prevention

1. **Enforce MFA**, especially for accounts holding Admin-level access. This single control would
   have stopped this incident even after the password was compromised.
2. **Account lockout** after a small number of consecutive failed attempts (3-5 attempts)
   to prevent brute-force and credential-stuffing patterns from reaching a success.
3. **Alerting** on the exact pattern detected here (repeated failures followed by a success from the
   same source), so it's flagged in near-real-time.
4. Change the SQL query used to detect the failed-attempt threshold and the successful login from the same
   IP, into a recurring/automated check.

---

*Screenshots referenced in this incident (Python findings, SQL output, and this summary) are in
`screenshots/`. See the "Screenshots" section of the project README for what each one shows.*
