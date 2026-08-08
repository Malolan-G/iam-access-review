import pandas as pd

df_access = pd.read_csv("data/access_permissions.csv")
df_login = pd.read_csv("data/login_attempts.csv")
df_users = pd.read_csv("data/users.csv")

# Displaying row counts
print("Row Counts:\n")
print(f"access_permissions.csv: {len(df_access)} rows")
print(f"login_attempts.csv: {len(df_login)} rows")
print(f"users.csv: {len(df_users)} rows\n")

# Finding Terminated Users
terminated = df_users[df_users["employment_status"] == "Terminated"]
print("Terminated Users Are:\n")
print(f" {terminated}\n")

# Finding users without MFA
notMFA = df_users[df_users["mfa_enabled"] == False]
print("Users Without MFA Enabled Are:\n")
print(f"{notMFA}\n")

# Finding Inactive Employees Function (Not active for 90 days)
def isInactive(df, refDate):
        Login = pd.to_datetime(df["last_login"])
        refDT = pd.Timestamp(refDate)
        timeDiff = refDT - Login
        inactive = (timeDiff > pd.Timedelta(days=90)) & (df["employment_status"] == "Active")
        return inactive


# Finding Inactive Employees
inactive_employees = (isInactive(df_users, "2026-08-05")) & (df_users["employment_status"] == "Active")
print("Inactive Users Are:\n")
print(f"{df_users[inactive_employees]}\n")


## JOINS:

# Joining users with permissions
df_joinedUA = pd.merge(
    df_users,
    df_access,
    on = "user_id",
    how = "inner" # Default Join
)
print(f"Users Joined with Permissions:\n")
print(f"{df_joinedUA}\n")

# Terminated Users with Access
df_haveAccess = df_joinedUA[(df_joinedUA["employment_status"] == "Terminated") | ((df_joinedUA["employment_status"] == "Active") & (isInactive(df_joinedUA, "2026-08-05")) )]
print(f"Terminated or Inactive Users with Access Are:\n")
print(f"{df_haveAccess}\n")

# Admin access w/o business need
df_adminAccess = df_access[(df_access["permission_level"] == "Admin") & (df_access["business_need"].isnull())]
print(f"Users with Unnecessary Admin Access Are:\n")
print(f"{df_adminAccess}\n")

# SUSPICIOUS IP'S

df_statusFail = df_login[df_login["status"] == "FAILURE"]

# Failed attempts by source IP
df_failIP = df_statusFail.groupby("source_ip").size().sort_values(ascending=False)
df_failIP = df_failIP.rename("Login Attempts")
print(f"Failed Login Attempts per IP\n")
print(f"{df_failIP}\n")

# Failed attempts by username
df_failUser = df_statusFail.groupby("username").size().sort_values(ascending=False)
df_failUser = df_failUser.rename("Login Attempts")
print(f"Number of Failed Login Attempts for each User:\n")
print(f"{df_failUser}\n")

# IP's exceeding threshold
df_threshIP = df_failIP[df_failIP > 3]
print(f"IP's Exceeding Failed Login Threshold Are:\n")
print(f"{df_threshIP}\n")

# Logins outside business hours
df_loginDT = pd.to_datetime(df_login["timestamp"]).dt.hour
business_hours = df_login[(df_loginDT < 9) | (df_loginDT >= 17)]
print(f"Logins Outside of Business Hours:\n")
print(f"{business_hours}\n")

# Successful logins from an IP that generated repeated failures
threshIP_logins = df_login[df_login["source_ip"].isin(df_threshIP.index)]
loginFailIP = threshIP_logins[threshIP_logins["status"] == "SUCCESS"]
print(f"Successful Logins from an IP that Generated Repeated Failures Are:\n")
print(f"{loginFailIP}\n")

# Users without MFA involved in suspicious activity
suspicionMarker = df_login[(df_login["source_ip"].isin(df_threshIP.index))|((df_loginDT < 9) | (df_loginDT >= 17))|(df_login["country"] != "United States")|(df_login["user_id"].isin(loginFailIP["user_id"]))]
marker_users = pd.merge(
        suspicionMarker,
        df_users,
        on = "user_id"
)
suspiciousMFA = marker_users[marker_users["mfa_enabled"] == False]
suspiciousMFA = suspiciousMFA.drop_duplicates("username")
print(f"A List of All Suspicious Users (without MFA enabled)\n")
print(f"{suspiciousMFA}\n")