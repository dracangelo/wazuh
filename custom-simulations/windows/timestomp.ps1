# Backdate a temporary file's LastWriteTime. PowerShell script-block logging (4104) feeds rule
# 100875; the file is removed afterwards.
$f = Join-Path $env:TEMP ("dv_timestomp_" + [guid]::NewGuid().ToString("N") + ".txt")
try {
    Set-Content -Path $f -Value "dv"
    (Get-Item -Path $f).LastWriteTime = (Get-Date).AddDays(-2)
} finally {
    Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
}
