# Marker: failed network logon for dv_canary_user, which produces Security 4625 (rule 100702).
# The IPC$ connection never succeeds; clean up the failed mapping if Windows created one.
net use \\127.0.0.1\IPC$ /user:dv_canary_user BadPass1 2>$null | Out-Null
net use \\127.0.0.1\IPC$ /delete 2>$null | Out-Null
