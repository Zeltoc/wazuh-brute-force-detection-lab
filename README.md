# Wazuh SIEM Lab - Brute Force & Credential Access Detection

**Tools:** Wazuh 4.x, Sysmon (SwiftOnSecurity config), NetExec (nxc), Hydra  
**Platform:** Proxmox homelab - Ubuntu 22.04 (Wazuh manager), Windows 11 (monitored endpoint)  
**MITRE ATT&CK:** T1110.001, T1550.002, T1531, T1078

---

## Objective

Set up a SIEM environment to detect a brute force attack against a Windows endpoint, confirm the built-in detection rules fire correctly, then write custom rules that reduce noise and improve fidelity over the defaults. Document the full detection chain from the attacker's first NTLM handshake through account lockout.

---

## Environment

| VM | OS | Role | IP |
|---|---|---|---|
| wazuh-manager | Ubuntu 22.04 | Wazuh Server + Dashboard | 192.168.1.x |
| DESKTOP-72VLLG0 | Windows 11 | Monitored endpoint (Wazuh agent + Sysmon) | 192.168.1.162 |
| kali | Kali Linux | Attacker | 192.168.1.36 |

Sysmon deployed on the Windows VM using the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config). Wazuh agent configured to ingest both the Security event channel and the Sysmon Operational channel.

---

## Attack Simulation

### Scenario 1 - NTLM Brute Force via SMB (T1110.001)

```bash
nxc smb 192.168.1.162 -u Administrator -p ~/big-list.txt
```

NetExec performs an NTLM authentication handshake before attempting credentials. This shows up as an anonymous NTLM logon (Event ID 4624, logon type 3, target: ANONYMOUS LOGON) *before* any failed attempts are logged - an artifact that turned out to be its own useful detection signal (see Rule 100004 below).

After the handshake, each password attempt generates a 4625 (failed logon) event with:
- `logonType: 3` - network logon, not interactive
- `authenticationPackageName: NTLM`
- `subStatus: 0xc000006a` - account exists, wrong password
- `ipAddress: 192.168.1.36` - attacker source

The `subStatus` distinction matters. `0xc000006a` means the account exists but the password is wrong. `0xc0000064` means the account doesn't exist at all. Attackers use this to confirm valid usernames before investing in a full brute force. In a real environment, seeing `0xc000006a` consistently across a burst of failures tells you the attacker already knows the account is valid.

Eventually the account locks out, generating a 4740 event.

---

## Detection Results - Built-in Rules

The following Wazuh built-in rules fired without any customization:

| Rule ID | Level | Description | Event |
|---|---|---|---|
| 60122 | 5 | Logon Failure - Unknown user or bad password | 4625 (each attempt) |
| 60204 | 10 | Multiple Windows Logon Failures | 4625 burst (aggregation) |
| 60115 | 9 | User account locked out (multiple login errors) | 4740 |
| 92652 | 6 | Successful Remote Logon - ANONYMOUS LOGON, possible pass-the-hash | 4624 (NTLM handshake) |
| 60118 | 3 | Windows Workstation Logon Success | 4624 (local UAC elevation - benign) |

### Unexpected Finding - Rule 92652

Before any 4625 failures appeared, Wazuh fired rule 92652 for an ANONYMOUS LOGON from `192.168.1.36`. This was NetExec performing its NTLM negotiation handshake. Windows logs it as a successful anonymous logon (4624), which Wazuh correctly flags as a potential pass-the-hash staging indicator.

In a real SOC, this alert would fire *before* the brute force volume alerts - it's an earlier and potentially higher-confidence signal depending on your environment. An anonymous NTLM logon from an external host is unusual outside of very specific legacy configurations.

### False Positive Noted - Rule 60118

Two 60118 "Windows Workstation Logon Success" events appeared at 22:05. Reviewing the raw event data showed these came from `consent.exe` via `::1` (localhost) for a local account - a UAC elevation prompt on the machine, not a successful brute force. The attacker never got in; the Administrator account locked out before any password succeeded.

This is worth documenting because it's representative of real analyst work: a logon success alert appearing in the middle of a brute force sequence looks alarming until you read the source IP and process name.

---

## Custom Detection Rules

The built-in rules cover the basics but have some gaps worth addressing:

- **60122** fires on *any* failed logon at level 5 - broad by design but generates noise from service accounts, local auth failures, etc.
- **60204** aggregates failures but isn't scoped to specific attack characteristics like NTLM-only or targeting privileged accounts.
- **92652** fires on *all* anonymous NTLM logons, including benign localhost events from `::1` - which would false positive constantly in normal Windows operation.

The custom rules below tighten each of these.

### Rule File: `local_rules.xml`

```xml
<group name="custom_brute_force,windows_security,">

  <!--
    Rule 100002
    Purpose: Refine built-in 60122 to catch specifically NTLM network
             logon failures targeting the Administrator account.
             LogonType 3 = network logon (not interactive/RDP console).
             Filters out noise from local service auth failures.
    MITRE: T1110.001 - Brute Force: Password Guessing
  -->
  <rule id="100002" level="6">
    <if_sid>60122</if_sid>
    <field name="win.eventdata.targetUserName" type="pcre2">(?i)administrator</field>
    <field name="win.eventdata.logonType">3</field>
    <field name="win.eventdata.authenticationPackageName" type="pcre2">NTLM</field>
    <description>NTLM network authentication failure targeting Administrator account from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>brute_force,authentication_failed,</group>
  </rule>

  <!--
    Rule 100003
    Purpose: Escalate to Critical when 5+ Rule 100002 events fire
             within 120 seconds. Tighter than built-in 60204 and scoped
             to confirmed NTLM attacks against Administrator specifically.
    MITRE: T1110.001 - Brute Force: Password Guessing
  -->
  <rule id="100003" level="12" frequency="5" timeframe="120">
    <if_matched_sid>100002</if_matched_sid>
    <description>CRITICAL: Brute force attack - 5+ NTLM failures against Administrator within 120s [T1110.001]</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>brute_force,authentication_failed,</group>
  </rule>

  <!--
    Rule 100004
    Purpose: Refine built-in 92652 to filter out localhost anonymous
             NTLM logons (::1 / 127.0.0.1), which are benign system events.
             Fires only on externally-sourced handshakes - an indicator of
             brute force reconnaissance or pass-the-hash staging.
             In this lab, NetExec triggered this before any credentials
             were attempted.
    MITRE: T1110.001, T1550.002
  -->
  <rule id="100004" level="10">
    <if_sid>92652</if_sid>
    <field name="win.eventdata.ipAddress" type="pcre2">^(?!::1$|127\.0\.0\.1$|-).*</field>
    <field name="win.eventdata.authenticationPackageName" type="pcre2">NTLM</field>
    <description>Anonymous NTLM remote logon from external host $(win.eventdata.ipAddress) - brute force handshake or pass-the-hash staging [T1550.002]</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1550.002</id>
    </mitre>
    <group>brute_force,authentication_success,pth_staging,</group>
  </rule>

</group>
```

---

## Detection Results - Custom Rules

| Rule ID | Level | Description | Fired |
|---|---|---|---|
| 100004 | 10 | Anonymous NTLM handshake from external host | First alert before failures started |
| 100002 | 6 | NTLM failure targeting Administrator from 192.168.1.36 | Every attempt |
| 100003 | 12 | CRITICAL - 5+ failures within 120s | Fired and re-triggered as attack continued |

Rule 100003 fired twice within the attack window because the frequency counter resets and re-triggers as additional events land. In a production environment this keeps escalating alerts active for the duration of an ongoing attack rather than firing once and going quiet.

---

## Full Attack Chain Timeline

```
22:20:00.413  100004 (lvl 10)  - Anonymous NTLM logon from 192.168.1.36
                                  NetExec NTLM handshake, pre-auth recon
                                  MITRE: T1550.002

22:20:05      100002 (lvl 6)   - 4625 failure #1, Administrator, NTLM, logonType 3
22:20:07      100002 (lvl 6)   - 4625 failure #2
22:20:09      100002 (lvl 6)   - 4625 failure #3
22:20:11      100002 (lvl 6)   - 4625 failure #4
22:20:13      100003 (lvl 12)  - CRITICAL: 5th failure, frequency threshold hit
                                  MITRE: T1110.001

22:20:15–21   100002 (lvl 6)   - Continued failures
22:20:23      100003 (lvl 12)  - CRITICAL: re-triggered
              60115  (lvl 9)   - Account lockout (4740), Administrator
                                  MITRE: T1531
```

---

## subStatus Reference

The `subStatus` field in 4625 events is useful for triage and is worth knowing:

| subStatus | Meaning | Analyst note |
|---|---|---|
| `0xc000006a` | Account exists, wrong password | All failures in this lab - confirms attacker is targeting a real account |
| `0xc0000064` | Account does not exist | Username enumeration, attacker guessing accounts |
| `0xc0000234` | Account locked out | Attack already triggered lockout policy |
| `0xc0000072` | Account disabled | Account exists but is disabled |

---

## Lessons Learned

**The anonymous logon is the earliest signal.** Rule 100004 fired before any 4625 events. In a real environment, tuning on this pattern (external NTLM anonymous logon) gives you a head start on brute force detection before the volume-based rules have time to aggregate.

**subStatus tells you more than the alert description.** The built-in alert says "unknown user or bad password" - the subStatus says specifically which one. That distinction affects triage priority and informs whether you're dealing with enumeration or targeted credential attack.

**False positive awareness matters.** The 60118 logon success in the middle of the brute force sequence looked suspicious at first. Reading the raw event - `consent.exe`, source `::1`, local account - cleared it immediately. Getting comfortable reading raw event data rather than just alert descriptions is what separates useful triage from noise.

**Rule chaining is more useful than single-event detections.** 100002 alone generates plenty of alerts. 100003 chaining off it with a frequency threshold is what makes the detection actionable - it's the difference between "there were some failures" and "something is actively attacking this account right now."

---

## Repo Structure

```
wazuh-brute-force-detection-lab/
├── README.md
├── alerts/
│   └── wazuh-alerts-4.x-2026.05.06#*.json
├── rules/
│   └── local_rules.xml
└── screenshots/
    ├── 01-dashboard-overview.png
    ├── 02-4625-flood-filtered.png
    ├── 03-full-event-timeline.png
    ├── 04-attack-chain-closeup.png
    └── 05-custom-rules-firing.png

```

---

## References

- [Wazuh Rules Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK T1550.002 - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Windows Security Event ID Reference - Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
