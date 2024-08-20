# Block Webshell creation for Servers

## Query Overview

### Description
This query identifies activities triggered by the Attack Surface Reduction (ASR) rule "Block Webshell creation for Servers" and aggregates additional context from the Microsoft ASR to MITRE-ATT&CK Mapping Project.

#### MITRE ATT&CK Mappings
- **T1505.003** - *Web Shell* (Sub-technique)

### References
- [Microsoft ASR Rule Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-webshell-creation-for-servers)

## Defender for Endpoint and Sentinel Query

```kusto
let ASRTOATTACKCCSV = externaldata(
    ASR_Rule_Name: string,Rule_GUID: string,Description: string,Mapping_type: string,Mitre_Attck_ID: string,target_type: string,Mitre_Attck_Name: string,target_ref: string,Refs: string,Advanced_hunting_action_type: string,Dependencies: string
)[@"https://raw.githubusercontent.com/CTI-Driven/Microsoft-ASR-to-MITRE-ATTACK-Mapping-Project/main/PDF_CSV_Files/ASRTOATTACKCSV.csv"]
with (format="csv", ignoreFirstRecord=True);
let ASRTOATTACKCMapping = ( ASRTOATTACKCCSV | summarize Techniques_ID_Mapping = make_set(Mitre_Attck_ID), ASR_Rule_Name = make_set(ASR_Rule_Name), Descriptions = make_set(Description),Mapping_types = make_set(Mapping_type), target_types = make_set(target_type), Techniques_Name_Mapping = make_set(Mitre_Attck_Name), target_refs = make_set(target_ref), ASR_Refs = make_set(Refs) by Rule_GUID );
DeviceEvents
| where Timestamp > ago(24hr)
| extend RuleId = tostring(parse_json(AdditionalFields).RuleId)
| where RuleId == "a8f5898e-1dc8-49a9-9878-85004b8a61e6"
| join kind=leftouter ASRTOATTACKCMapping on $left.RuleId == $right.Rule_GUID
| summarize arg_max(Timestamp, *) by DeviceId, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| project-reorder Timestamp, DeviceName, ActionType, ASR_Rule_Name, Techniques_ID_Mapping, Techniques_Name_Mapping, Descriptions, ASR_Refs, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ProcessCommandLine
| order by Timestamp asc 