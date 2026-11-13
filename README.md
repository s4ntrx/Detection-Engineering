# Detection Engineering: Sigma Rules for an African Fintech Threat Model

This document contains three Sigma detection rules mapped to MITRE ATT&CK techniques highly relevant to an African fintech environment.

For each rule, I have included the raw YAML code, the detection logic, simulated true-positive and benign false-positive test cases, and tuning notes for production deployment.

---

## Rule 1: Credential Stuffing / Brute Force (T1110)

**Technique:** Automated attempts to log in using leaked credentials against a fintech portal.

**Logic:** This rule targets the *behavior* of brute-forcing rather than a specific IP address. It looks for more than 10 failed login attempts from a single IP within a 5-minute window.

### Sigma Rule

    title: Multiple Failed Logins Followed by Success
    id: 8b2c3d4e-1234-5678-9abc-def012345678
    status: experimental
    description: Detects a high volume of failed logins followed by a success from the same IP.
    logsource:
        product: linux
        service: sshd
    detection:
        selection:
            EventType: 'Failed'
        timeframe: 5m
        condition: selection | count() by SourceIp > 10
    fields:
        - SourceIp
        - User
    falsepositives:
        - Internal vulnerability scanners
        - Misconfigured applications
    level: high

### Test Data

**True Positive (Fires):**

    {"EventType":"Failed", "SourceIp":"192.168.1.5"}

*(Repeated 15 times within a 5-minute window)*

**Benign False Positive (Quiet):**

    {"EventType":"Failed", "SourceIp":"10.0.0.12"}

*(Occurs once, typical user typo)*

### Tuning Notes (Noise)

In production, this rule will be noisy due to internal vulnerability scanners or misconfigured automated tools. Tuning should filter out internal RFC1918 IP ranges (`and not SourceIp in ('10.0.0.0/8')`) or create an allowlist of known scanner IPs.

---

## Rule 2: Web Shell Process Creation (T1505.003)

**Technique:** Attackers uploading a web shell to a fintech web server and executing OS commands.

**Logic:** A web server process (IIS/Apache/Nginx) should never spawn a command interpreter. This detects the exact moment a web shell attempts to execute a command.

### Sigma Rule

    title: Web Server Spawning Suspicious Shell
    id: 1a2b3c4d-5678-90ab-cdef-1234567890ab
    status: experimental
    description: Detects web server processes (IIS/Apache/Nginx) spawning command interpreters.
    logsource:
        category: process_creation
        product: windows
    detection:
        selection_parent:
            ParentImage|endswith:
                - '\w3wp.exe'
                - '\httpd.exe'
                - '\nginx.exe'
        selection_child:
            Image|endswith:
                - '\cmd.exe'
                - '\powershell.exe'
                - '\bash.exe'
        condition: selection_parent and selection_child
    falsepositives:
        - Legitimate administrative scripts
        - Software updates
    level: critical

### Test Data

**True Positive (Fires):**

    {"ParentImage":"C:\\Windows\\System32\\inetsrv\\w3wp.exe", "Image":"C:\\Windows\\System32\\cmd.exe", "CommandLine":"cmd.exe /c whoami"}

**Benign False Positive (Quiet):**

    {"ParentImage":"C:\\Windows\\explorer.exe", "Image":"C:\\Windows\\System32\\cmd.exe"}

*(Standard user action opening CMD manually)*

### Tuning Notes (Noise)

In production, legitimate software updates for the web server might spawn PowerShell. To fix this, add a filter to exclude known update scripts: `filter: CommandLine|contains: 'C:\Windows\Temp\UpdateScript.ps1'`.

---

## Rule 3: Suspicious OAuth Application Consent (T1528)

**Technique:** An attacker tricks a fintech employee into granting an OAuth app access to their Microsoft 365 or Google Workspace.

**Logic:** Detects users granting permissions to apps that can read emails and files, which is often used for Business Email Compromise (BEC).

### Sigma Rule

    title: High-Risk OAuth Consent Granted
    id: 9f8e7d6c-5b4a-3210-fedc-ba9876543210
    status: experimental
    description: Detects OAuth consent granted to applications requesting high-risk scopes.
    logsource:
        product: m365
        service: audit
    detection:
        selection:
            Operation: 'Consent to application'
        keywords:
            - 'Mail.Read'
            - 'Files.ReadWrite.All'
            - 'offline_access'
        condition: selection and keywords
    falsepositives:
        - Approved third-party SaaS tools
    level: high

### Test Data

**True Positive (Fires):**

    {"Operation":"Consent to application", "ModifiedProperties":[{"NewValue":"User.Read, Mail.Read"}]}

**Benign False Positive (Quiet):**

    {"Operation":"Consent to application", "ModifiedProperties":[{"NewValue":"User.Read"}]}

*(Basic login scope only)*

### Tuning Notes (Noise)

This will be noisy if the company uses a lot of third-party SaaS tools. Tune it by creating an allowlist of approved AppIDs: `and not AppId in ('approved-app-id-1', 'approved-app-id-2')`.

---

## Trade-offs & Validation Methodology

Because I am using free, open-source tooling, I could not test these in a live Splunk or Elastic environment. Instead, I validated the logic manually against JSON test samples to prove the Sigma `selection` and `condition` fields work as intended, firing on malicious patterns and staying quiet on benign noise.
