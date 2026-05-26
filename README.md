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


