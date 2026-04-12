# Active Directory PowerShell Cheatsheet
### For AD Admins & Service Desk Engineers
Full write-up: https://karanth.ovh/powershell-cheatsheet-ad-admins-service-desk-engineers

---

## Prerequisites

```powershell
# Import the Active Directory module
Import-Module ActiveDirectory

# Check if module is loaded
Get-Module ActiveDirectory

# Always run PowerShell as Administrator for AD tasks
```

---

## User account management

```powershell
# Get a single user
Get-ADUser -Identity "jsmith"

# Get user with all properties
Get-ADUser -Identity "jsmith" -Properties *

# Search by display name
Get-ADUser -Filter {DisplayName -like "*John*"} -Properties DisplayName,EmailAddress

# Search by email address
Get-ADUser -Filter {EmailAddress -eq "john.smith@company.com"} -Properties EmailAddress

# Search users in a specific OU
Get-ADUser -Filter * -SearchBase "OU=Staff,DC=company,DC=com"

# Find all disabled users
Get-ADUser -Filter {Enabled -eq $false} | Select-Object Name, SamAccountName

# Find users who haven't logged in for 90 days
$date = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $date -and Enabled -eq $true} `
    -Properties LastLogonDate | Select-Object Name, LastLogonDate
```

---

## Unlock and password tasks

```powershell
# Check if a user account is locked
Get-ADUser -Identity "jsmith" -Properties LockedOut | Select-Object Name, LockedOut

# Unlock a user account
Unlock-ADAccount -Identity "jsmith"

# Reset a user's password
Set-ADAccountPassword -Identity "jsmith" -Reset `
    -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force)

# Force password change at next logon
Set-ADUser -Identity "jsmith" -ChangePasswordAtLogon $true

# Reset password AND force change at next logon
Set-ADAccountPassword -Identity "jsmith" -Reset `
    -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force)
Set-ADUser -Identity "jsmith" -ChangePasswordAtLogon $true

# Check password last set date
Get-ADUser -Identity "jsmith" -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet

# Find users with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires |
    Select-Object Name, SamAccountName
```

---

## Enable and disable accounts

```powershell
# Disable a user account
Disable-ADAccount -Identity "jsmith"

# Enable a user account
Enable-ADAccount -Identity "jsmith"

# Check if account is enabled or disabled
Get-ADUser -Identity "jsmith" | Select-Object Name, Enabled

# Find all disabled accounts in an OU
Get-ADUser -Filter {Enabled -eq $false} -SearchBase "OU=Staff,DC=company,DC=com" |
    Select-Object Name, SamAccountName
```

---

## Group management

```powershell
# Get all members of a group
Get-ADGroupMember -Identity "IT-Admins" | Select-Object Name, SamAccountName

# Check what groups a user belongs to
Get-ADPrincipalGroupMembership -Identity "jsmith" | Select-Object Name

# Add a user to a group
Add-ADGroupMember -Identity "IT-Admins" -Members "jsmith"

# Remove a user from a group
Remove-ADGroupMember -Identity "IT-Admins" -Members "jsmith" -Confirm:$false

# Add multiple users to a group at once
Add-ADGroupMember -Identity "IT-Admins" -Members "jsmith","jdoe","mjones"

# Create a new security group
New-ADGroup -Name "VPN-Users" -GroupScope Global -GroupCategory Security `
    -Path "OU=Groups,DC=company,DC=com"

# Find all groups a user is a member of (including nested)
Get-ADUser -Identity "jsmith" -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf
```

---

## Computer account management

```powershell
# Find a computer in AD
Get-ADComputer -Identity "PC001" -Properties *

# Search computers by name pattern
Get-ADComputer -Filter {Name -like "PC*"} | Select-Object Name

# Find all computers in an OU
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=company,DC=com" |
    Select-Object Name

# Find computers that haven't logged in for 90 days
$date = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $date} -Properties LastLogonDate |
    Select-Object Name, LastLogonDate

# Disable a computer account
Disable-ADAccount -Identity "PC001$"

# Find the last logged on user of a computer
Get-WmiObject -ComputerName "PC001" -Class Win32_ComputerSystem |
    Select-Object UserName
```

---

*More at [karanth.ovh](https://karanth.ovh)*