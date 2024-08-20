# LOLBins CTI-Driven
<p align="center">
<img src="../ASRtoATTACKlogo.png" style="border-radius:60px;width:20%;height:auto"> 
</p>

# Advanced hunting ASR Rules KQL:

| ASR Rules KQL Query | Technique IDs Mapping | Mapping types | Technique Names |
|---------------|-----------------------|---------------|-------------------------|
| [Block credential stealing from the Windows local security authority subsystem (lsass.exe)](ASR_Rules_KQL_Query/AsrLsassCredentialTheft-9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2.md) | T1003.001 | mitigates | LSASS Memory |
| [Block execution of potentially obfuscated scripts](ASR_Rules_KQL_Query/AsrObfuscatedScript-5beb7efe-fd9a-4556-801d-275e5ffc04cc.md) | T1027.010, T1027.013 | mitigates | Command Obfuscation, Encrypted/Encoded File |
| [Block use of copied or impersonated system tools (preview)](ASR_Rules_KQL_Query/AsrUseOfCopiedorImpersonatedSystemtools-c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb.md) | T1036.003, T1036.005 | mitigates | Rename System Utilities, Match Legitimate Name or Location |
| [Block process creations originating from PSExec and WMI commands](ASR_Rules_KQL_Query/AsrPsexecWmiChildProcess-d1e49aac-8f56-4280-b9ba-993a6d77406c.md) | T1047, T1569.002, T1570 | mitigates | Windows Management Instrumentation, Service Execution, Lateral Tool Transfer |
| [Block Office applications from injecting code into other processes](ASR_Rules_KQL_Query/AsrOfficeProcessInjection-75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84.md) | T1055 | mitigates | Process Injection |
| [Block JavaScript or VBScript from launching downloaded executable content](ASR_Rules_KQL_Query/AsrScriptExecutableDownload-d3e037e1-3eb8-44c8-a917-57927947596d.md) | T1059.005, T1059.007 | mitigates | Visual Basic, JavaScript |
| [Block abuse of exploited vulnerable signed drivers](ASR_Rules_KQL_Query/AsrVulnerableSignedDriver-56a863a9-875e-4185-98a7-b882c64b5ce5.md) | T1068, T1543, T1543.003 | mitigates | Exploitation for Privilege Escalation, Create or Modify System Process, Windows Service |
| [Block untrusted and unsigned processes that run from USB](ASR_Rules_KQL_Query/AsrUntrustedUsbProcess-b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4.md) | T1091 | mitigates | Replication Through Removable Media |
| [Block Win32 API calls from Office macros](ASR_Rules_KQL_Query/AsrOfficeMacroWin32ApiCalls-92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b.md) | T1106 | mitigates | Native API |
| [Block Office application from creating child processes](ASR_Rules_KQL_Query/AsrOfficeChildProcess-d4f940ab-401b-4efc-aadc-ad5f3c50688a.md) | T1137, T1137.001, T1137.002, T1137.003, T1137.004, T1137.005, T1137.006, T1204.002 | mitigates | Office Application Startup, Office Template Macros, Office Test, Outlook Forms, Outlook Home Page, Outlook Rules, Add-ins, Malicious File |
| [Block Office communication application from creating child processes](ASR_Rules_KQL_Query/AsrOfficeCommAppChildProcess-26190899-1602-49e8-8b27-eb1d0a1ce869.md) | T1137.005, T1203 | mitigates | Outlook Rules, Exploitation for Client Execution |
| [Block Office applications from creating executable content](ASR_Rules_KQL_Query/AsrExecutableOfficeContent-3b576869-a4ec-4529-8536-b80a7769e899.md) | T1137.006 | mitigates | Add-ins |
| [Block executable files from running unless they meet a prevalence, age, or trusted list criteria](ASR_Rules_KQL_Query/AsrUntrustedExecutable-01443614-cd74-433a-b99e-2ecdc07bfc25.md) | T1204 | mitigates | User Execution |
| [Block Adobe Reader from creating child processes](ASR_Rules_KQL_Query/AsrAdobeReaderChildProcess-7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c.md) | T1204.002 | mitigates | Malicious File |
| [Block executable content from email client and webmail](ASR_Rules_KQL_Query/AsrExecutableEmailContent-be9ba2d9-53ea-4cdc-84e5-9b1eeee46550.md) | T1204.002 | mitigates | Malicious File |
| [Use advanced protection against ransomware](ASR_Rules_KQL_Query/AsrRansomware-c1db55ab-c21a-4637-bb3f-a12568109d35.md) | T1486 | mitigates | Data Encrypted for Impact |
| [Block Webshell creation for Servers](ASR_Rules_KQL_Query/AsrWebshellcreationforServers-a8f5898e-1dc8-49a9-9878-85004b8a61e6.md) | T1505.003 | mitigates | Web Shell |
| [Block persistence through WMI event subscription](ASR_Rules_KQL_Query/AsrPersistenceThroughWmi-e6db77e5-3df2-4cf1-b95a-636979351e5b.md) | T1546.003 | mitigates | Windows Management Instrumentation Event Subscription |
| [Block rebooting machine in Safe Mode (preview)](ASR_Rules_KQL_Query/AsrrebootingmachineinSafeMode-33ddedf1-c6e0-47cb-833e-de6133960387.md) | T1562.009 | mitigates | Safe Mode Boot |
