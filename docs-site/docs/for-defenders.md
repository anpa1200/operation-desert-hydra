---
id: for-defenders
title: What Defenders Should Do Right Now
sidebar_label: For Defenders
---

**1. Baseline your RMM deployments.**
det_mw_0007 is the most consistently documented MuddyWater technique across all five source tiers. It fires on ScreenConnect, SimpleHelp, AteraAgent, Level, and PDQConnect from non-standard paths. But it needs a baseline of authorized deployments first. Build the baseline; the detection logic is already written.

**2. Enable PowerShell Script Block Logging fleet-wide.**
One Group Policy change:
```
Computer Configuration → Administrative Templates → Windows Components
→ Windows PowerShell → Turn on PowerShell Script Block Logging → Enabled
```
This unlocks det_mw_0003 Rule B and all three det_mw_0009 rules. No other change required.

**3. Configure Sysmon ProcessAccess against lsass.exe.**
Without it, LSASS credential dumping detection is binary-name-only. Renamed Mimikatz and custom C++ dumpers are invisible. Add `<ProcessAccess onmatch="include">` targeting `lsass.exe` to `sysmon.xml`.

**4. Hunt for PT43M now.**
Query your Task Scheduler Operational logs for any task with a `RepetitionInterval` of `PT43M`. If you find one you cannot attribute to a known deployment, investigate — BugSleep uses this specific interval for C2 beaconing. Build a baseline of authorized scheduled tasks first; PT43M is rare enough to be worth investigating.
