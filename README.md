# IAM Access Review & Suspicious Login Investigation

This is a simulated Identity and Access Management (IAM) access review for a fictional company, using
synthetic user, permission and login data to identify excessive permissions, inactive accounts,
missing MFA, terminated users who still have access, and any suspicious login activity - then
documenting that data in a way that would be suitable for a security analyst: with evidence of the
problem, its severity and recommendations for how to fix it.

## Scenario

A fictional company asked for an access review covering one week of activity
(2026-07-29 to 2026-08-05). This review aimed to investigate the company's 
user roster, system access grants, and login logs to determine, who has access 
they shouldn't, who's missing basic controls like MFA and does anything in the 
login activity look like an actual attack rather than routine noise?

## Tools Used

- **Python (pandas)** - data loading, filtering, and joins (`scripts/access_review.py`)
- **SQL (SQLite)** - the same investigation re-built as relational queries (`sql/investigation_queries.sql`)
- **CSV** - the raw synthetic data source
- **Matplotlib** - the summary chart in `screenshots/`
- **GitHub** - version control and project hosting

## Project Structure

```
IAM Access Review Project/
├── data/
│   ├── users.csv                  # 20 synthetic user records
│   ├── access_permissions.csv     # 29 system access grants
│   └── login_attempts.csv         # 154 login events
├── scripts/
│   └── access_review.py           # pandas-based analysis
├── sql/
│   ├── iam_review.db              # SQLite database (data/*.csv imported)
│   └── investigation_queries.sql  # 7 SQL queries mirroring the Python analysis
├── reports/
│   ├── access_review_report.md    # Full access review findings
│   └── incident_summary.md        # Suspicious-login incident writeup
├── screenshots/                   # Evidence images referenced by the reports
└── README.md
```

## Analysis Performed

Both the Python and SQL analyses cover the same ground, cross-checked against each other:

- Row counts and a data sanity check across all three source files
- Users with `employment_status = Terminated`
- Users with `mfa_enabled = False`
- Accounts inactive 90+ days (`last_login` vs. a reference date) that are still marked `Active`
- A join of users with permissions to find terminated/inactive users who still hold access, and
  admin-level grants with no recorded business justification
- Failed login attempts grouped by source IP and by username, to surface brute-force-style activity
- IPs whose failed-login count exceeds a certain threshold, then checked for any *successful* login
  afterward, reflecting the signature of a brute-force attack that was successful
- Users without MFA whose accounts show up in any of the above suspicious-activity checks

## Key Findings

| # | Finding | Severity |
|---|---|---|
| 1 | Terminated user (`U015`) retained `Write` access to the Customer Database | High |
| 2 | Active admin account (`U010`) has no MFA and was the target of a successful credential-stuffing-style login | High |
| 3 | Active account (`U004`) has no MFA | Medium |
| 4 | Admin-level access grant (`U004` --> Marketing Platform) has no documented business need | Medium |
| 5 | Stale account (`U016`), inactive 90+ days, still retains Cloud Console access | Medium |

Full detail, and remediation steps along with corresponding evidence for each finding are in
[`reports/access_review_report.md`](reports/access_review_report.md).

The most significant single event was five failed logins against `U010` from the same IP followed by
a success eleven minutes later, which has an in-depth investigation in
[`reports/incident_summary.md`](reports/incident_summary.md).

## Screenshots

| Screenshot | What it shows |
|---|---|
| `screenshots/python_findings.png` | Output from `scripts/access_review.py` : terminated users, missing MFA, stale accounts, undocumented admin access, and the flagged IP/login pattern |
| `screenshots/sql_output.png` | The equivalent findings reproduced in SQL: the MFA query, the users and permissions `JOIN` for admin access, and the `GROUP BY` failed-attempts-per-IP query |
| `screenshots/suspicious_login_summary.png` | The incident query, `HAVING` + subquery, which isolated the one successful login from a flagged IP, plus the six raw login rows that make up the pattern |
| `screenshots/failed_logins_by_ip_chart.png` | Bar chart of failed login attempts by source IP, with the two IPs exceeding the suspicious-activity threshold highlighted |

## Recommendations

1. Revoke access immediately for any terminated user still holding live permissions.
2. Enforce MFA for all accounts, prioritizing anyone with admin-level access.
3. Require a documented business justification at the time any permission is granted.
4. Add account lockout or rate limiting feature after a small number of failed login attempts.
5. Turn the SQL queries in this project from a one-time exercise to a recurring requirement.

## Limitations

- The data in this exercise is synthetic and was generated specifically for this exercise. So, any findings and their severities within the organization are illustrative of the method used to assess this organization's risk and not a reflection of the actual risks that exist within that organization.
- The dataset only contains data from a single 8-day window of time and therefore does not allow for assessment of any seasonal or recurring access to the system.
- The lack of any logging from the endpoint server, the network or the identity provider (SSO/IdP) has limited the investigation to the data in the three source CSV files.  
- The thresholds used, like 90 days for staleness or 3 failed attempts for suspicious IP,  would need comparison against real organizational baselines if used in production.

## What I Learned

- The MFA value in this data is stored as a literal text value like `'FALSE'`, not as a real boolean. 
  I had to check the stored value carefully for each of these fields before writing my filters as I 
  could not assume a normal true/false type.
- Getting comfortable with the sqlite3 command line itself took some trial and error. I had to learn
  where the database file actually lived as well as how to open it; then learn how commands like 
  `.tables` and `.read` work. I also learned that `.read` looks for the file relative to wherever 
  the terminal was already sitting, not relative to the database file, so I had to `cd` into the 
  right folder first before it would find my SQL file.
- One of the concepts that I somewhat struggled with was the difference between `WHERE` and `HAVING`.
  I initially tried to filter for failed logins using `HAVING status = 'FAILURE'` after a `GROUP BY`, and
  the count came out different from when I used `WHERE` instead. I quickly learned that `HAVING` was filtering
  groups after they were already combined, whereas `WHERE` filters individual rows before the grouping happens. 
  Seeing the two give different outputs on the same data is what made the rule stick.
- I also learned to slow down and jot my thought process along with basic pseudocode before writing a query. 
  For example, when attempting to find users without MFA that were involved in suspicious activity, I wrote down 
  what my suspicion marker would include and how I would include all its filters in one line without any errors. 
- I learned how to actually read and understand raw log files instead of just staring at rows of
  timestamps and IPs. Working with CSVs like this was new to me, so a lot of this project was about
  learning how to pull useful information out of them, which included: grouping events by IP or by user, 
  counting how often something happens, and comparing timestamps to spot patterns. The shift to reading 
  CSV's as a record of behavior, was probably the biggest practical skill I picked up from this project.