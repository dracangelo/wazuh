# Point a new, uniquely named HKCU CLSID at a non-existent DLL in %TEMP%, which Sysmon 13 records
# for rule 100877. The key is removed in the finally block.
$guid = "{" + [guid]::NewGuid().ToString() + "}"
$key = "HKCU:\Software\Classes\CLSID\$guid\InprocServer32"
try {
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name "(Default)" -Value (Join-Path $env:TEMP "dv_canary.dll")
    Start-Sleep -Seconds 2
} finally {
    Remove-Item -Path "HKCU:\Software\Classes\CLSID\$guid" -Recurse -Force -ErrorAction SilentlyContinue
}
