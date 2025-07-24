# Credential-Harvesting
**Suspicious activity was detected from a user account**

## Example Scenario:
A standard user, who was recently hired, works from home and was flagged by administrators for potentially malicious activity. This user accesses the necessary company resources through RDP but unusual interactions with the processes ```rundll32.exe``` and ```comsvcs.dll``` was detected and need to be analyzed along with the creation of the ```svchost-exe.dmp``` file. The goal is to investigate malicious use of built-in Windows utilities (```rundll32.exe```, and ```comsvcs.dll```) to dump process memory.
</br>_Note: ```rundll32.exe``` is responsable for running system utilities and configuration tools that are implemented as DLL exports. ```comsvcs.dll``` is primarily used by legitimate COM+ applications, but attackers often abuse its ```MiniDump``` function to dump process memory._

---

## IoC Discovery Plan:
1. Check DeviceProcessEvents for the Windows utilities ```rundll32.exe``` and ```comsvcs.dll```
2. Check DeviceFileEvents for the ```svchost-exe.dmp``` dump file
3. Isolate system
4. Remove all malicious files/processes

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

1. I looked for the process ```comsvcs.dll``` and the file ```rundll32.exe``` on the user's system using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-admin"
| where FileName == "rundll32.exe"
| where ProcessCommandLine contains "comsvcs.dll"
```
The following events results were displayed:
<img width="1668" height="285" alt="image" src="https://github.com/user-attachments/assets/8f69b741-94fb-4933-9d16-9ccc8a9a5ab6" />
<img width="1660" height="378" alt="image" src="https://github.com/user-attachments/assets/ecdaac03-1a64-403f-8ecf-73feda3055e5" />
In itself, these attributes are not a reason for concern, but it was necessary to search the system for the svchost file which would indicate suspicious activity.

2. I searched for the ```svchost-exe.dmp``` file using the query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-admin"
| where FileName contains "svchost"
```
The following results were displayed:
<img width="1668" height="242" alt="image" src="https://github.com/user-attachments/assets/2078e60b-ff88-41db-8b73-a634e317489b" />
From this I was able to see that the connection was done remotely and from a computer named "desktop-ni4tdje" which is my host computer. This concludes that the user was able to gain access to the admin account. _Note: Although there are more logon successes, these are from me logging in minutes before starting the lab._

3. After the suspicious activity was verified, the user's computer was isolated.
<img width="1432" height="764" alt="image" src="https://github.com/user-attachments/assets/d5146c24-2c0e-4fed-aa99-f1957befa36b" />

4. Then, navigating through the system, remove the svchost-exe.dmp file from the system ensuring the system is back to its secure state.

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
