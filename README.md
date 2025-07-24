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
This verified that the dump file ```svchost-exe.dmp``` was created and present on the system which concludes malicious activity.</br>
_Note: I was not able to open the .dmp file due to certain limitations and complications with the lab environment._

3. After the suspicious activity was verified, the user's computer was isolated.
<img width="1432" height="764" alt="image" src="https://github.com/user-attachments/assets/d5146c24-2c0e-4fed-aa99-f1957befa36b" />

4. Then, navigating through the system, I removed the ```svchost-exe.dmp``` file from the system ensuring the system was back to its secure state.

---

## Chronological Events

1. The user ran the malicious script 
2. The file creation was verifed and the system was isolated
3. The file was removed

---

## Summary

From the user's device , ```rojas-admin```, a malicious script was run which downloaded RDP session information to a file named ```svchost-exe.dmp```. This file pulled information from the Windows attributes ```rundll32.exe``` and ```comsvcs.dll```. The system was isolated and all malicious files were removed.

---

## Response Taken
The device was isolated and the administrator was notified. All malicious files were deleted.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: July 24, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July  24, 2025`  | `Jeremiah Rojas`   
