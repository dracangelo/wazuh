# Benign encoded command: the child powershell process carries -EncodedCommand on its command
# line, which Sysmon 1 exposes to rule 100856.
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output dv_canary"))
& powershell.exe -NoProfile -EncodedCommand $b64 | Out-Null
