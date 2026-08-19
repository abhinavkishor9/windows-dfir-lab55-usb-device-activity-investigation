# Timeline

# Investigation Timeline

| Order | Time | Source | Activity | Result |
|---:|---|---|---|---|
| 1 | — | Registry | Windows device enumeration tree inspected | `USB` branch identified |
| 2 | — | Registry | `USBSTOR` availability checked | `USBSTOR` unavailable |
| 3 | — | Registry | `Enum\USB` inspected | USB-related entries identified |
| 4 | — | Registry | `DeviceClasses` inspected | Device-interface entries identified |
| 5 | — | Registry | `MountedDevices` investigated | Supporting storage mappings reviewed |
| 6 | — | System Log | Device-provider search performed | No matching events returned |
| 7 | — | System Log | Broad USB message search performed | No matching events returned |
| 8 | 19-08-2026 07:09–07:17 | Event Viewer | System and Security activity reviewed | General Windows activity observed |
| 9 | — | Storage | `Get-Disk` executed | VMware NVMe disk identified |
| 10 | — | Storage | `Get-Volume` executed | Current volume baseline investigated |
| 11 | 19-08-2026 | Security | Event ID 4624 reviewed | Session context investigated |
| 12 | 19-08-2026 07:17:10 | Security | Example Event ID 4624 examined | Logon Type 5 / SYSTEM |
| 13 | 19-08-2026 07:09–07:32 | Sysmon | Event ID 1 reviewed | Process creation telemetry available |
| 14 | 19-08-2026 06:42–07:32 | Sysmon | Event ID 3 reviewed | Network telemetry available |
| 15 | 18-08-2026–19-08-2026 | File System | Recent user files reviewed | Recent filesystem activity identified |
| 16 | — | DFIR Analysis | Evidence sources correlated | USB activity assessment performed |
| 17 | — | DFIR Analysis | Evidence limitations documented | Historical USB connection not established |
| 18 | — | DFIR Analysis | Final assessment completed | USB data transfer not established |

---

