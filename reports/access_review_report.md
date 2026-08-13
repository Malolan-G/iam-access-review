# IAM Access Review Report

**Project:** IAM Access Review & Suspicious Login Investigation (simulated using synthetic data)
**Review period:** 2026-07-29 to 2026-08-05
**Reviewed by:** Malolan G.

## Executive Summary

This review analyzed 20 user accounts, 29 access-permission grants, and 154 login events across a synthetic company environment to identify identity and access management (IAM) risks. During these reviews, one terminated employee was found to have access to the systems still, two active user accounts did not have MFA enabled (with one of them having admin-level access to the system), there was one grant of admin-level access without any documented business justification for such access and one user account was found to be inactive for over 90 days yet still retained access to the system. Though none of these individual findings are particularly concerning, their combined presence suggests the presence of a gap in access permissions and security hygiene within this organization. As such, the level of risk associated with these findings is assessed as **Medium-High**.

## Scope

In this review, the user accounts, access permissions and login activities of the company were analyzed. The purpose of the review was to determine if there were any security-related issues within the company's systems. The review of the data provided on the user accounts, permissions and login attempts only covered the access and authentication aspects of the company's systems.

## Data Reviewed

| Source | Rows | Description |
|---|---|---|
| `users.csv` | 20 | Employee identity records: department, role, employment status, last login, MFA status |
| `access_permissions.csv` | 29 | System-level permission grants per user, with business justification field |
| `login_attempts.csv` | 154 | Login events: timestamp, source IP, status, country |

Analysis was performed twice, independently, using Python/pandas (`scripts/access_review.py`) and SQL
queries against a SQLite database (`sql/investigation_queries.sql`), with results cross-checked between
the two for consistency.

## Findings

### 1. Terminated user retained access

- **Evidence:** User `U015` (Olivia Martinez, Sales) has `employment_status = Terminated` (last login
  2026-03-15) but still holds an active `Write` permission on the Customer Database system
  (`access_permissions.csv`, business need: "Sales lead and account management").
- **Why it matters:** The offboarding process should include revocation of access for terminated 
  employees. A live credential that is tied to a former employee presents a risk of unauthorized 
  access to company data.
- **Severity:** High
- **Recommended action:** Immediately revoke all system access for `U015`. Add an automated or
  checklist-based offboarding step that ties access revocation to the `Terminated` status change.

### 2. Missing MFA on active accounts

- **Evidence:** Two active accounts have `mfa_enabled = FALSE`: `U004` (David Lee, Sales
  Representative) and `U010` (Jack Turner, Network Engineer). `U010` also holds `Admin`-level access
  to Cloud Console.
- **Why it matters:** MFA is a baseline control against credential-based attacks (like phishing,
  and password reuse). The absence of MFA is more severe when the user has elevated
  privileges. Refer to the incident in `incident_summary.md`, where `U010`'s account was the
  target of a successful login following repeated failed attempts from a single IP.
- **Severity:** High for `U010`; Medium for `U004`.
- **Recommended action:** Systemically enable MFA org-wide, prioritizing accounts with admin-level system access,
  and treat `U010` as the most urgent given the suspicious login activity.

### 3. Excessive privileges / undocumented business need

- **Evidence:** `U004` (David Lee, Sales Representative) holds `Admin`-level access to the Marketing
  Platform with no `business_need` recorded (`access_permissions.csv` row for U004/Marketing
  Platform). A second, lower-severity instance exists for `U014` (Noah Baker), who holds `Read`
  access to Payroll with no documented business need.
- **Why it matters:** Admin-level access without a recorded justification cannot be validated as
  necessary, and a Sales Representative holding Admin rights on a Marketing system is inconsistent
  with least-privilege access based on role. Undocumented grants also make future access reviews
  harder to audit.
- **Severity:** Medium
- **Recommended action:** Require a documented business justification for every permission grant,
  especially Admin-level ones, at the time access is requested. Review `U004`'s Marketing Platform
  Admin grant with their manager and downgrade or revoke if unjustified.

### 4. Stale account with retained access

- **Evidence:** `U016` (Peter Nguyen, Warehouse Associate) is marked `Active` but has not logged in
  since 2026-04-10 — more than 90 days before the review date (2026-08-05) — and still holds `Read`
  access to Cloud Console.
- **Why it matters:** Long-dormant accounts that retain access are an unnecessary attack surface;
  if compromised, activity may go unnoticed longer since the account isn't in regular use and
  wouldn't trigger "unusual activity for this user" style detection as easily.
- **Severity:** Medium
- **Recommended action:** Confirm current employment status with HR/manager. If still employed but
  inactive, review whether Cloud Console access is still needed; if not, disable the account or
  revoke access pending confirmation.

## Risk Level Summary

| Finding | Severity |
|---|---|
| Terminated user retained access (U015) | High |
| Missing MFA + admin access (U010) | High |
| Missing MFA (U004) | Medium |
| Undocumented admin access (U004) | Medium |
| Stale account with access (U016) | Medium |

**Overall assessment: Medium-High.** No evidence of an active, ongoing large-scale breach was found.
While this dataset contains a variety of security-related events, there are two instances that deserve special attention.  
The first instance is the terminated user who still has live access to the system.  The second incident is the admin user 
with no MFA who displays signs of targeted login attempts (detailed in `incident_summary.md`); Both warrant a prompt response.

## Recommended Remediation

1. Revoke `U015`'s access immediately (terminated employee).
2. Enforce MFA for `U010` and `U004`, prioritizing `U010`.
3. Validate or revoke `U004`'s undocumented Admin grant on Marketing Platform.
4. Confirm `U016`'s employment/activity status and re-scope or disable access accordingly.
5. Add recurring access reviews using the queries in `sql/investigation_queries.sql`
   so that suspicious activities such as these are caught earlier next time.

## Limitations

- The data in this exercise is synthetic and was generated specifically for this exercise. So, any findings and their severities within the organization are illustrative of the method used to assess this organization's risk and not a reflection of the actual risks that exist within that organization.
- The dataset only contains data from a single 8-day window of time and therefore does not allow for assessment of any seasonal or recurring access to the system.
- The lack of any logging from the endpoint server, the network or the identity provider (SSO/IdP) has limited the investigation to the data in the three source CSV files.  
- The thresholds used, like 90 days for staleness or 3 failed attempts for suspicious IP,  would need comparison against real organizational baselines if used in production.
