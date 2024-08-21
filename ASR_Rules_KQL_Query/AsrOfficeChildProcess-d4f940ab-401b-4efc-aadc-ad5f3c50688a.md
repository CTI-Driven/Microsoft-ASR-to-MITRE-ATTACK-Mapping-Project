# Block Office application from creating child processes

## Query Overview

### Description
This query identifies activities triggered by the Attack Surface Reduction (ASR) rule "Block Office application from creating child processes" and aggregates additional context from the Microsoft ASR to MITRE-ATT&CK Mapping Project.

#### MITRE ATT&CK Mappings
- **T1137** - *Office Application Startup* (Technique)
- **T1137.001** - *Office Template Macros* (Sub-technique)
- **T1137.002** - *Office Test* (Sub-technique)
- **T1137.003** - *Outlook Forms* (Sub-technique)
- **T1137.004** - *Outlook Home Page* (Sub-technique)
- **T1137.005** - *Outlook Rules* (Sub-technique)
- **T1137.006** - *Add-ins* (Sub-technique)
- **T1204.002** - *Malicious File* (Sub-technique)

### References
- [Microsoft ASR Rule Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-all-office-applications-from-creating-child-processes)

## Defender for Endpoint and Sentinel Query

```kusto
// Replace "Timestamp" with "TimeGenerated" when running this KQL query in Microsoft Sentinel.
let ASRTOATTACKCCSV = externaldata(
    ASR_Rule_Name: string,Rule_GUID: string,Description: string,Mapping_type: string,Mitre_Attck_ID: string,target_type: string,Mitre_Attck_Name: string,target_ref: string,Refs: string,Advanced_hunting_action_type: string,Dependencies: string
)[@"https://raw.githubusercontent.com/CTI-Driven/Microsoft-ASR-to-MITRE-ATTACK-Mapping-Project/main/PDF_CSV_Files/ASRTOATTACKCSV.csv"]
with (format="csv", ignoreFirstRecord=True);
let ASRTOATTACKCMapping = ( ASRTOATTACKCCSV | summarize Techniques_ID_Mapping = make_set(Mitre_Attck_ID), ASR_Rule_Name = make_set(ASR_Rule_Name), Descriptions = make_set(Description),Mapping_types = make_set(Mapping_type), target_types = make_set(target_type), Techniques_Name_Mapping = make_set(Mitre_Attck_Name), target_refs = make_set(target_ref), ASR_Refs = make_set(Refs) by Rule_GUID );
DeviceEvents
| where Timestamp > ago(24hr)
| where ActionType in ("AsrOfficeChildProcessAudited", "AsrOfficeChildProcessBlocked")
| extend RuleId = tostring(parse_json(AdditionalFields).RuleId)
| join kind=leftouter ASRTOATTACKCMapping on $left.RuleId == $right.Rule_GUID
| summarize arg_max(Timestamp, *) by DeviceId, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| project-reorder Timestamp, DeviceName, ActionType, ASR_Rule_Name, Techniques_ID_Mapping, Techniques_Name_Mapping, Descriptions, ASR_Refs, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ProcessCommandLine
| order by Timestamp asc 
