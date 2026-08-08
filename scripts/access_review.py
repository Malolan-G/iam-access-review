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
def isActive(df, refDate):
        Login = pd.to_datetime(df["last_login"])
        refDT = pd.Timestamp(refDate)
        timeDiff = refDT - Login
        inactive = (timeDiff > pd.Timedelta(days=90)) & (df["employment_status"] == "Active")
        return inactive


# Finding Inactive Employees
inactive_employees = (isActive(df_users, "2026-08-05")) & (df_users["employment_status"] == "Active")
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
df_haveAccess = df_joinedUA[(df_joinedUA["employment_status"] == "Terminated") | ((df_joinedUA["employment_status"] == "Active") & (isActive(df_joinedUA, "2026-08-05")) )]
print(f"Terminated or Inactive Users with Access Are:\n")
print(f"{df_haveAccess}\n")

# Admin access w/o business need
df_adminAccess = df_access[(df_access["permission_level"] == "Admin") & (df_access["business_need"].isnull())]
print(f"Users with Unnecessary Admin Access Are:\n")
print(f"{df_adminAccess}\n")