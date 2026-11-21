# Run elevated on each Windows target (and the extra DC lines on domain controllers only).
auditpol /set /subcategory:"Logon"                          /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"        /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"      /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events"     /success:enable   # 4698 task created
# Domain controllers only:
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable   # 4769
auditpol /set /subcategory:"Directory Service Access"       /success:enable                       # 4662 (DCSync)

# PowerShell script block logging (4104)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1