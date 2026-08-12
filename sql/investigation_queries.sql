-- Users without MFA
SELECT user_id, name, mfa_enabled
FROM users
WHERE mfa_enabled = 'FALSE';

-- Terminated users
SELECT user_id, name, employment_status
FROM users
WHERE employment_status = 'Terminated';

-- Inactive accounts with access
SELECT user_id, name, last_login
FROM users
WHERE employment_status = 'Active'
    AND (julianday('2026-08-05') - julianday(last_login)) > 90;

-- Users with admin permission (JOINS)
SELECT users.user_id, users.name, permissions.permission_level
FROM users
INNER JOIN permissions
    ON users.user_id = permissions.user_id
WHERE permissions.permission_level = 'Admin';

-- Failed attempts by IP
SELECT source_ip, COUNT(*)
FROM login
WHERE status = 'FAILURE'
GROUP BY source_ip;

-- Failed attempts by username
SELECT username, COUNT(*)
FROM login
WHERE status = 'FAILURE'
GROUP BY username;

-- Successful logins from suspicious IPs (Sub-Query)
SELECT source_ip, COUNT(*)
FROM login
WHERE status = 'SUCCESS'
    AND source_ip IN(SELECT source_ip FROM login WHERE status = 'FAILURE' GROUP BY source_ip HAVING COUNT(*) > 3)
GROUP BY source_ip;