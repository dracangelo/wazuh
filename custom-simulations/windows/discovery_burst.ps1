# Eight read-only discovery commands from one account trip the frequency rule 100862.
$commands = @("whoami", "hostname", "ipconfig", "systeminfo", "tasklist", "netstat -an", "arp -a",
              "nltest /domain_trusts")
foreach ($c in $commands) {
    cmd /c $c 2>$null | Out-Null
}
