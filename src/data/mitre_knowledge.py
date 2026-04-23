# MITRE ATT&CK techniques — the bible of cyber attacks
# Real techniques used by real hacker groups
# Source: https://attack.mitre.org

MITRE_TECHNIQUES = [
    {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries guess passwords to gain access to accounts without prior knowledge. Commonly targets SSH, RDP, and web login portals.",
        "threat_groups": "APT28, Lazarus Group, FIN5",
        "indicators": "Multiple failed login attempts from single IP, targeting root or admin accounts",
        "next_techniques": "T1021 Remote Services, T1078 Valid Accounts",
        "mitigation": "Account lockout policies, MFA, fail2ban, restrict SSH to key-based auth only"
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries use a single password against many accounts to avoid lockouts. Harder to detect than traditional brute force.",
        "threat_groups": "APT33, APT28, Cozy Bear",
        "indicators": "Low volume login failures across many accounts, often from cloud IPs",
        "next_techniques": "T1078 Valid Accounts, T1550 Use Alternate Auth Material",
        "mitigation": "MFA on all accounts, monitor for distributed login failures, conditional access policies"
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries steal data using protocols like DNS, ICMP, or Tor to bypass monitoring. Large data transfers to unusual IPs are a key indicator.",
        "threat_groups": "APT32, Lazarus Group, FIN7",
        "indicators": "Large outbound transfers to unknown IPs, use of Tor exit nodes, encrypted channels to unusual destinations",
        "next_techniques": "T1567 Exfiltration to Cloud Storage",
        "mitigation": "Egress filtering, DLP tools, block Tor exit nodes, monitor outbound traffic volume"
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries use PowerShell to execute malicious commands, download payloads, and move laterally. Encoded commands are used to evade detection.",
        "threat_groups": "APT29, FIN7, Lazarus Group, Carbanak",
        "indicators": "Encoded PowerShell commands (-enc flag), unusual parent processes spawning PowerShell, script block logging events",
        "next_techniques": "T1055 Process Injection, T1105 Ingress Tool Transfer",
        "mitigation": "PowerShell logging, constrained language mode, block encoded commands via AppLocker"
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries inject malicious code into legitimate processes to hide malware and escalate privileges. svchost.exe is a common target.",
        "threat_groups": "APT29, APT32, Turla, Cobalt Group",
        "indicators": "Unusual child processes from svchost.exe, unexpected network connections from system processes",
        "next_techniques": "T1003 Credential Dumping, T1021 Remote Services",
        "mitigation": "Endpoint protection, process behavior monitoring, restrict process creation"
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries use HTTP/HTTPS to communicate with C2 servers, blending in with normal web traffic.",
        "threat_groups": "APT28, APT29, Lazarus Group",
        "indicators": "Beaconing behavior, unusual HTTP requests to low-reputation domains, high frequency small packets",
        "next_techniques": "T1105 Ingress Tool Transfer, T1041 Exfiltration Over C2",
        "mitigation": "Web proxy filtering, SSL inspection, DNS monitoring, threat intelligence feeds"
    },
    {
        "id": "T1021.001",
        "name": "Remote Services: RDP",
        "tactic": "Lateral Movement",
        "description": "Adversaries use Remote Desktop Protocol to move laterally through a network after initial compromise.",
        "threat_groups": "APT41, FIN6, Ryuk ransomware operators",
        "indicators": "RDP connections from unusual sources, off-hours access, new accounts used for RDP",
        "next_techniques": "T1003 Credential Dumping, T1486 Data Encrypted for Impact",
        "mitigation": "Disable RDP if not needed, restrict RDP to VPN only, enable NLA, monitor RDP logs"
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "description": "Adversaries encrypt files on target systems to deny access and demand ransom. Often follows credential theft and lateral movement.",
        "threat_groups": "Ryuk, REvil, Conti, LockBit, BlackCat",
        "indicators": "Mass file renaming, high disk I/O, shadow copy deletion, ransom notes",
        "next_techniques": "T1490 Inhibit System Recovery",
        "mitigation": "Offline backups, EDR solutions, disable VSS deletion rights, network segmentation"
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence",
        "description": "Adversaries use legitimate credentials to access systems, making detection very difficult.",
        "threat_groups": "APT29, FIN7, APT33",
        "indicators": "Logins from unusual locations or times, use of service accounts for interactive login",
        "next_techniques": "T1021 Remote Services, T1098 Account Manipulation",
        "mitigation": "MFA, privileged access workstations, behavioral analytics, zero trust architecture"
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit vulnerabilities in internet-facing applications such as web servers, VPNs, and APIs.",
        "threat_groups": "APT41, APT10, Hafnium",
        "indicators": "Unusual error codes, unexpected outbound connections from web servers, WAF alerts",
        "next_techniques": "T1059 Command Scripting, T1505 Server Software Component",
        "mitigation": "Patch management, WAF, vulnerability scanning, network segmentation"
    }
]