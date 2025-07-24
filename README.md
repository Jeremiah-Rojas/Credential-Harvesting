# Credential-Harvesting
**Suspicious activity was detected from a user account**

## Example Scenario:
A standard user, who was recently hired, works from home and was flagged by administrators for potentially malicious activity. This user accesses the necessary company resources through RDP but unusual interactions with the processes ```rundll32.exe``` and ```comsvcs.dll``` was detected and need to be analyzed along with the creation of the ```svchost-exe.dmp``` file. The goal is to investigate malicious use of built-in Windows utilities (```rundll32.exe```, and ```comsvcs.dll```) to dump process memory.
</br>_Note: ```rundll32.exe``` is responsable for running system utilities and configuration tools that are implemented as DLL exports. ```comsvcs.dll``` is primarily used by legitimate COM+ applications, but attackers often abuse its ```MiniDump``` function to dump process memory._

---

## IoC Discovery Plan:
1. Check DeviceProcessEvents for the Windows utilities ```rundll32.exe``` and ```comsvcs.dll```
2. Check DeviceFileEvents for the ```svchost-exe.dmp``` dump file

---
## Steps Taken by Bad Actor
1. Execute Malicious Powershell script: 
```
$ps = (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore)
if($ps){$id = $ps[0].OwningProcess} else {$id = (Get-Process svchost)[0].Id }
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $id $env:TEMP\svchost-exe.dmp full
```
Note: This powershell command checks for an active RDP session, dumps the memory of the process that owns the sessions, and the memory dump is saved to a temp folder.

---

## Steps Taken

1. First look for logon failures using the following query (I narrowed down the results by entering in the DeviceName):
```kql
DeviceProcessEvents
| where DeviceName == "rojas-admin"
| where FileName == "rundll32.exe"
| where ProcessCommandLine contains "comsvcs.dll"
```
The following events results were displayed:
<img width="1668" height="285" alt="image" src="https://github.com/user-attachments/assets/8f69b741-94fb-4933-9d16-9ccc8a9a5ab6" />
<img width="1660" height="378" alt="image" src="https://github.com/user-attachments/assets/ecdaac03-1a64-403f-8ecf-73feda3055e5" />
Due to the number of failed logon attempts (7) in a period of three seconds, I concluded that this was a brute force attempt.

2. Next, I wanted to verify if the malicious user was able to successfully logon so I slightly changed the query to search for logon successes:
```kql
DeviceFileEvents
| where DeviceName == "rojas-admin"
| where FileName contains "svchost"
```
The following results were displayed:
<img width="1668" height="242" alt="image" src="https://github.com/user-attachments/assets/2078e60b-ff88-41db-8b73-a634e317489b" />
From this I was able to see that the connection was done remotely and from a computer named "desktop-ni4tdje" which is my host computer. This concludes that the user was able to gain access to the admin account. _Note: Although there are more logon successes, these are from me logging in minutes before starting the lab._

---

## Chronological Events

1. The user brute forced the admin password and logged in
2. The user used powershell ISE to write and run the script
3. The script downloaded an image and printed text to the screen

---

## Summary

The administrator's device was compromised via brute force, ```rojas-admin``` and a script ```IT-testing.ps1``` was run. This script downloaded an image and printed text to the screen but did not implement permanent damage. This attack, although simple, stresses the importance having strong passwords and avoiding the reuse of old passwords since they can be easily compromised.

---

## Response Taken
The administrator's device was compromised via brute force, ```rojas-admin```. The device was isolated and the administrator was notified. All malicous files were deleted and a anti-malware scan was peformed.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: July 12, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July  14, 2025`  | `Jeremiah Rojas`   
