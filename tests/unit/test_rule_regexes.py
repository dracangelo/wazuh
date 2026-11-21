"""Run each rule's regex/pcre2 field patterns against sample log text. Catches typos offline."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

RULES = Path(__file__).resolve().parents[2] / "rules" / "wazuh" / "linux"


def _load():
    out = {}
    for p in sorted(RULES.glob("0*.xml")):
        root = ET.fromstring(f"<root>{p.read_text()}</root>")
        for r in root.iter("rule"):
            pats = [e.text for e in r.findall("regex")] + [e.text for e in r.findall("field") if e.get("type") == "pcre2"]
            out[int(r.get("id"))] = {"regex": [e.text for e in r.findall("regex")],
                                     "fields": {e.get("name"): e.text for e in r.findall("field")}, "pats": pats}
    return out


R = _load()


def hit(rid, text, key=None):
    pats = [R[rid]["fields"][key]] if key else R[rid]["regex"]
    return all(re.search(p, text) for p in pats)


def test_sudo_rules():
    assert hit(100206, "sudo: dv : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash")
    assert hit(100206, "COMMAND=/usr/bin/su -")
    assert not hit(100206, "COMMAND=/usr/bin/apt update")
    assert hit(100207, "COMMAND=/usr/bin/chmod u+s /tmp/x") and hit(100207, "COMMAND=/usr/bin/chmod 4755 /tmp/x")
    assert not hit(100207, "COMMAND=/usr/bin/chmod 644 /tmp/x") and not hit(100207, "COMMAND=/usr/bin/chmod 0755 /x")
    assert hit(100208, "COMMAND=/usr/sbin/visudo") and not hit(100208, "COMMAND=/usr/bin/ls /etc")


def test_syslog_rules():
    assert hit(100301, "usermod[1]: add 'dv' to group 'sudo'")
    assert hit(100301, "gpasswd[1]: user dv added by root to group wheel")
    assert not hit(100301, "usermod[1]: add 'dv' to group 'users'")
    assert hit(100302, "crontab[9]: (root) REPLACE (root)") and not hit(100302, "crontab[9]: (root) LIST (root)")
    assert hit(100303, "passwd: pam_unix(passwd:chauthtok): password changed for root")
    assert not hit(100303, "passwd: pam_unix(passwd:chauthtok): password changed for alice")
    assert hit(100500, "systemd[1]: Stopped Security Auditing Service.")
    assert hit(100501, "systemd[1]: Stopping firewalld - dynamic firewall daemon...")


def test_fim_paths_and_perms():
    f = lambda rid: R[rid]["fields"]["file"]
    assert re.search(f(100310), "/etc/shadow") and not re.search(f(100310), "/etc/shadowx")
    assert re.search(f(100311), "/etc/sudoers.d/dv_test") and re.search(f(100313), "/home/a/.ssh/authorized_keys")
    assert re.search(f(100314), "/etc/cron.d/dv_test") and re.search(f(100315), "/etc/systemd/system/x.service")
    assert re.search(f(100316), "/etc/ld.so.preload") and re.search(f(100324), "/var/www/html/s.php")
    assert not re.search(f(100324), "/var/www/html/index.html")
    perm = R[100319]["fields"]["syscheck.perm"]
    assert re.search(perm, "rwxr-xr-x") and not re.search(perm, "rw-r--r--")
    suid = R[100320]["fields"]["syscheck.perm_after"]
    assert re.search(suid, "rwsr-xr-x") and not re.search(suid, "rwxr-xr-x")


def test_auditd_arg_rules():
    assert hit(100404, 'a0="ncat" a1="-e" a2="/bin/sh"') and not hit(100404, 'a0="nc" a1="-z" a2="host"')
    assert hit(100406, 'a0="find" a1="/usr/bin" a2="-perm" a3="-4000"')
    assert not hit(100406, 'a0="find" a1="/usr/bin" a2="-name" a3="ls"')
    assert hit(100402, 'a0="curl" a1="-o" a2="/tmp/dv_x/dl"') and not hit(100402, 'a0="curl" a1="-o" a2="/home/u/f"')
    assert hit(100407, 'a0="rm" a1="-f" a2="/home/u/.bash_history"') and not hit(100407, 'a0="rm" a1="/tmp/x"')
    assert re.search(R[100401]["fields"]["audit.exe"], "/tmp/dv_x/dv_payload")
    assert not re.search(R[100401]["fields"]["audit.exe"], "/usr/bin/env")
    assert hit(100410, 'a0="/tmp/linpeas.sh"') and hit(100503, "type=CONFIG_CHANGE msg=audit(1): auid=1000 ses=3 op=remove_rule key=(null)")
    assert not hit(100503, "type=CONFIG_CHANGE msg=audit(1): auid=4294967295 ses=4294967295 op=remove_rule")
    assert hit(100502, "type=MAC_STATUS msg=audit(1): enforcing=0 old_enforcing=1")


def test_web_rules():
    assert hit(100600, 'GET / HTTP/1.1" 200 "sqlmap/1.7.2#stable"') and not hit(100600, 'GET / "Mozilla/5.0"')
    assert hit(100601, 'User-Agent: () { :; }; echo x') and hit(100601, "ua=%28%29%20%7B")
    assert hit(100602, "GET /i.php?page=../../../../etc/passwd") and not hit(100602, "GET /docs/../index.html")
    assert hit(100603, "GET /uploads/x.php?cmd=whoami") and not hit(100603, "GET /index.php?page=2")
    assert hit(100604, 'X-Api: ${jndi:ldap://h/x}') and hit(100604, 'q=%24%7Bjndi%3Aldap')
    assert hit(100605, "id=1%20UNION%20SELECT%20NULL") and hit(100605, "id=1 or 1=1")
    assert not hit(100605, "GET /products?id=12")


def test_marker_rules():
    f = R[100100]["fields"]["file"]
    assert re.search(f, "/etc/dv_fim_test.txt") and re.search(f, "/home/u/dv_fim_test.txt")
    assert not re.search(f, "/etc/dv_fim_test.txt.bak") and not re.search(f, "/etc/not_dv_fim_test.txt")
    assert hit(100110, "dv_canary: DV_CANARY id=1763700000") and not hit(100110, "dv_canary: hello")
    assert hit(100112, '10.0.0.5 - - [21/Nov/2026] "GET /dv_canary HTTP/1.1" 404 0')
    assert hit(100112, '"GET /dv_canary?x=1 HTTP/1.1" 200') and not hit(100112, '"GET /dv_canary_other HTTP/1.1" 200')
