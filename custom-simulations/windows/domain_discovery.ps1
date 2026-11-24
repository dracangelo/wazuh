# Domain and network trust enumeration. The commands are read-only; a non-domain host simply
# returns an error, but Sysmon still records the process creation for rule 100873.
cmd /c net view 2>$null | Out-Null
cmd /c nltest /domain_trusts 2>$null | Out-Null
