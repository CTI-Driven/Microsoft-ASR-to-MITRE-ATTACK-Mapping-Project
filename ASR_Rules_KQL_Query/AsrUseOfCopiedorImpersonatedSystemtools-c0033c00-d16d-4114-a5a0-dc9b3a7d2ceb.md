# Block use of copied or impersonated system tools (preview)

## Query Overview

### Description
This query identifies activities triggered by the Attack Surface Reduction (ASR) rule "Block use of copied or impersonated system tools (preview)" and aggregates additional context from the Microsoft ASR to MITRE-ATT&CK Mapping Project.

#### MITRE ATT&CK Mappings
- **T1036.003** - *Rename System Utilities* (Sub-technique)
- **T1036.005** - *Match Legitimate Name or Location* (Sub-technique)

### References
- [Microsoft ASR Rule Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-use-of-copied-or-impersonated-system-tools-preview)

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
| extend RuleId = tostring(parse_json(AdditionalFields).RuleId)
| where RuleId == "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"
| join kind=leftouter ASRTOATTACKCMapping on $left.RuleId == $right.Rule_GUID
| summarize arg_max(Timestamp, *) by DeviceId, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| project-reorder Timestamp, DeviceName, ActionType, ASR_Rule_Name, Techniques_ID_Mapping, Techniques_Name_Mapping, Descriptions, ASR_Refs, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ProcessCommandLine
| order by Timestamp asc 
