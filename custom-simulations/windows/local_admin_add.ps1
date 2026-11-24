# Create a uniquely named local user and add it to Administrators, then remove both changes.
# Requires elevation. Rules 100860 (net localgroup add) and 100753 (4720) can fire.
$suffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
$user = "dv_admin_$suffix"
try {
    net user $user "Dv!Passw0rd_$suffix" /add 2>$null | Out-Null
    net localgroup Administrators $user /add 2>$null | Out-Null
    Start-Sleep -Seconds 2
} finally {
    net localgroup Administrators $user /delete 2>$null | Out-Null
    net user $user /delete 2>$null | Out-Null
}
