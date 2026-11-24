# Marker: create, modify and delete a uniquely named file in C:\Windows\Temp, which the agent
# snippet monitors in realtime. Rules 100703-100706 match dv_fim_test*.txt.
$f = Join-Path $env:TEMP ("dv_fim_test_" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".txt")
try {
    Set-Content -Path $f -Value "created"
    Start-Sleep -Seconds 3
    Add-Content -Path $f -Value "modified"
    Start-Sleep -Seconds 3
} finally {
    Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
}
