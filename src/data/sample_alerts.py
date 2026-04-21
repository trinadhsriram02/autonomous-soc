SAMPLE_ALERTS = [
    {
        "id": "alert_001",
        "type": "brute_force",
        "message": "Failed SSH login attempts: 847 failures in 60 seconds from IP 192.168.1.45 targeting user 'root'",
        "severity": "high",
        "timestamp": "2024-01-15 03:42:11"
    },
    {
        "id": "alert_002",
        "type": "normal_traffic",
        "message": "User john.doe logged in successfully from IP 10.0.0.12 at 09:15 AM",
        "severity": "low",
        "timestamp": "2024-01-15 09:15:03"
    },
    {
        "id": "alert_003",
        "type": "data_exfiltration",
        "message": "Unusual outbound traffic: 4.7GB transferred to external IP 185.220.101.42 (known Tor exit node) in 10 minutes",
        "severity": "critical",
        "timestamp": "2024-01-15 14:23:55"
    },
    {
        "id": "alert_004",
        "type": "malware",
        "message": "Process svchost.exe spawned child process powershell.exe with encoded payload on host DESKTOP-XK29",
        "severity": "critical",
        "timestamp": "2024-01-15 16:07:33"
    },
    {
        "id": "alert_005",
        "type": "normal_traffic",
        "message": "Scheduled backup job completed. 2.1GB transferred to backup server 10.0.1.5",
        "severity": "info",
        "timestamp": "2024-01-15 02:00:45"
    }
]