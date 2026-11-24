# Marker: write one Application-log event that rule 100700 recognises.
$id = [guid]::NewGuid().ToString("N").Substring(0, 8)
eventcreate /id 999 /l APPLICATION /t INFORMATION /so DV_CANARY /d "DV_CANARY id=$id" | Out-Null
