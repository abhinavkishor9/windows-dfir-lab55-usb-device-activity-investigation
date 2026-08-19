# Troubleshooting Notes 

## 1. USBSTOR Was Unavailable

### Problem

The expected USB mass-storage Registry artifact was not available.

The investigation did not attempt to create it.

### Observation

The expected `USBSTOR` artifact was unavailable on the endpoint.

### Resolution

The investigation was modified to use alternative USB-related artifacts.

The following sources were investigated:

- USB Registry enumeration.
- DeviceClasses.
- MountedDevices.
- Windows System events.
- Current storage state.
- User sessions.
- Sysmon telemetry.
- Filesystem activity.

### DFIR Lesson

A missing artifact should be documented as a limitation.

It should not be artificially created to produce a desired investigation result.

---

## 2. USB Enumeration Was Available

### Observation

The following command returned a `USB` branch:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum" |
Select-Object PSChildName
```

The USB-specific enumeration path was also available.

### Result

The endpoint returned:

```text
ROOT_HUB
ROOT_HUB20
ROOT_HUB30
VID_0E0F&PID_0002
VID_0E0F&PID_0003
VID_0E0F&PID_0003&MI_00
VID_0E0F&PID_0003&MI_01
VID_0E0F&PID_0007
VID_0E0F&PID_000A
```

### Interpretation

This confirms USB-related device enumeration information.

It does not automatically prove USB mass-storage usage.

### DFIR Lesson

Device enumeration artifacts must be interpreted according to the type of device represented.

---

## 3. DeviceClasses Returned Many Entries

### Observation

The DeviceClasses Registry path returned numerous GUID entries.

### Interpretation

This confirms that Windows maintains device-interface information.

However, DeviceClasses entries alone do not establish:

- USB flash-drive usage.
- Historical USB connection.
- File transfer.
- User attribution.

### DFIR Lesson

Supporting artifacts should be correlated with stronger evidence before drawing conclusions.

---

## 4. System Device-Provider Search Returned No Results

### Problem

The following query returned no results:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 500 |
Where-Object {
    $_.ProviderName -match "Kernel-PnP|UserPnp|DriverFrameworks"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Interpretation

No matching provider events were present in the queried 500-event window.

### Important Limitation

This does not prove that Windows never generated device-related events.

The search was limited to a specific number of recent events.

### DFIR Lesson

A bounded event search can establish what was found in the searched window, not what never existed on the system.

---

## 5. Broad USB System Search Returned No Results

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "System"
} -MaxEvents 1000 |
Where-Object {
    $_.Message -match "USB|USBSTOR|removable|storage|device"
} |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Observation

No matching events were returned.

### Interpretation

No matching USB-related messages were identified in the queried 1000-event window.

### DFIR Lesson

The result should be documented as:

> No matching events were identified in the queried window.

It should not be documented as:

> No USB activity occurred.

---

## 6. Current Disk Was NVMe

### Observation

`Get-Disk` returned:

```text
FriendlyName : VMware Virtual NVMe Disk
BusType      : NVMe
```

### Interpretation

The current storage device was a VMware virtual NVMe disk.

No current USB storage disk was identified.

### Limitation

Current disk state does not establish historical device state.

A device that is not currently connected may still have been connected previously.

### DFIR Lesson

Current-state artifacts and historical artifacts must not be treated as interchangeable.

---

## 7. Security Event 4624 Did Not Automatically Identify a User

### Observation

A reviewed Event ID 4624 showed:

```text
Logon Type: 5
Account Name: SYSTEM
```

### Interpretation

This was a service logon.

It was not treated as evidence of an interactive user session.

### DFIR Lesson

Event ID 4624 contains multiple logon types.

A successful logon event does not automatically identify a human user interacting with the endpoint.

---

## 8. Sysmon Event ID 1 Was Available

### Observation

Sysmon Event ID 1 returned numerous process creation events.

### Interpretation

Process telemetry is available for correlation.

### Limitation

A process such as `explorer.exe`, `powershell.exe`, `cmd.exe`, `robocopy.exe`, or `xcopy.exe` does not by itself prove USB activity.

### DFIR Lesson

Process telemetry becomes stronger when correlated with device, filesystem, and user evidence.

---

## 9. Sysmon Event ID 3 Was Available

### Observation

Sysmon Event ID 3 returned numerous network connection events.

### Interpretation

Network activity was present.

### Limitation

Network activity does not prove:

- USB activity.
- File transfer.
- Data exfiltration.
- Malicious behavior.

### DFIR Lesson

Network telemetry is supporting evidence and requires process and destination analysis.

---

## 10. Filesystem Activity Was Present

### Observation

Recent filesystem activity included screenshots, OneDrive files, recordings, and documents.

### Interpretation

The endpoint was actively being used.

### Limitation

Filesystem timestamps alone cannot establish that files were copied to removable media.

### DFIR Lesson

File activity should be correlated with a confirmed destination, process activity, and device evidence.

---

## 11. No USB Insertion Was Simulated

### Safety Decision

The investigation did not intentionally connect a USB storage device.

### Reason

The objective was to investigate the evidence already available on the endpoint.

Creating a USB connection solely to generate evidence would undermine the artifact-validation objective of the lab.

### DFIR Lesson

A realistic DFIR investigation must distinguish between naturally available evidence and evidence artificially generated for testing.

---

## 12. Do Not Create USBSTOR Artificially

### Safety Rule

Do not create a fake:

```text
USBSTOR
```

Registry path simply to make the investigation appear successful.

### Reason

The purpose of the lab is to document artifact availability.

Artificially creating the artifact would invalidate the evidence assessment.

---

## 13. Do Not Modify Device Registry Artifacts

The investigation did not modify:

- `Enum\USB`
- `DeviceClasses`
- `MountedDevices`
- Other Windows device Registry information

### DFIR Lesson

Forensic artifacts should be treated as evidence.

Investigation commands should be read-only wherever possible.

---

## 14. Do Not Clear Windows Event Logs

Do not use commands such as:

```powershell
wevtutil cl Security
```

or:

```powershell
wevtutil cl System
```

### Reason

The investigation depends on existing Windows telemetry.

Clearing logs would destroy potentially useful evidence.

---

## 15. Do Not Delete Registry Artifacts

The lab did not remove or alter USB-related Registry artifacts.

### Reason

The objective is artifact discovery and interpretation.

Deleting Registry artifacts would compromise the investigation.

---

