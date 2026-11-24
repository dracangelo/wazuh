# Create an alternate data stream on a temporary file, then remove the host file.
# Sysmon event 15 (FileCreateStreamHash) feeds rule 100876.
$f = Join-Path $env:TEMP ("dv_ads_" + [guid]::NewGuid().ToString("N") + ".txt")
try {
    Set-Content -Path $f -Value "dv"
    Set-Content -Path "$f:dvstream" -Value "dv_ads_canary"
} finally {
    Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
}
