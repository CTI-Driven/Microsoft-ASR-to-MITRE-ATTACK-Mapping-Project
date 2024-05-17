# Microsoft ASR to MITRE-ATTACK Mapping Project
**Description:**\
This project aims to bridge the gap between Microsoft Attack Surface Reduction (ASR) rules and MITRE ATT&CK by mapping ASR rules to their corresponding ATT&CK techniques. The primary goal is to enhance the understanding of how ASR rules align with the ATT&CK framework.
<br>

**Mapping Methodology:**\
The approach for mapping ASR (Attack Surface Reduction) rules to MITRE ATT&CK techniques draws inspiration from the following sources:

MITRE ATT&CK Enterprise Mitigations:
[ID: M1040](https://attack.mitre.org/mitigations/M1040/)
[ID: M1050](https://attack.mitre.org/mitigations/M1050/) \
Attack Control Framework Mappings: 
[Mapping Methodology](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/docs/mapping_methodology.md#)

##
**Last Updated:** Tue May 15 2024\
**ASR TO ATTACK:** [PDF](PDF_CSV_Files/ASRTOATTACKPDF.pdf) \
**ASR TO ATTACK:** [Google SpreadSheet Table](https://docs.google.com/spreadsheets/d/1OMsFsLsqoEXkZI4FjYm9Y2IzSBF6eAsT/edit?usp=sharing&ouid=118019733456378989878&rtpof=true&sd=true) \
**ASR TO ATTACK:** [STIX Visualizer](https://oasis-open.github.io/cti-stix-visualization/?url=https://raw.githubusercontent.com/CTI-Driven/Microsoft-ASR-to-MITRE-ATTACK-Mapping-Project/main/STIX2/ASR_ATTACK_STIX2.json) \
**Tidal Cyber Community Edition:** [Matrix](https://app.tidalcyber.com/share/d12b5a0d-a554-4782-b2d6-da5e5932600f) \
**References to Documentation for ASR rules:** [Microsoft ASR rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) 
# ASR Rules MITRE-ATTACK Navigator Coverage:
![ASRTOATTACK](Microsoft_ASR_to_MITREATTACK_Mapping_Layer.svg)

## Useful Use Cases of the Microsoft ASR to MITRE-ATT&CK Mapping Project:

1. **Heatmap Generation for Coverage Analysis**:
   - **Description**: Utilize the [ASR to ATT&CK Navigator Coverage](Mitre%20attack%20navigator/microsoft_asr_to_mitre-attack_mapping_layer.json) alongside the ATT&CK Navigator for the specific threats you are concerned about (e.g., the top 20 techniques used by ransomware groups).
   - **Benefit**: This allows you to generate a heatmap that visualizes the coverage provided by existing [Microsoft ASR rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference). By identifying the techniques already mitigated by ASR rules, you can prioritize efforts on techniques that are not yet covered.


2. **Integration with Threat Intelligence Platforms (TIPs)**:
   - **Description**: Streamline the [ASR to ATT&CK Navigator Coverage](Mitre%20attack%20navigator/microsoft_asr_to_mitre-attack_mapping_layer.json) or [ASR_STIX2](STIX2/ASR_ATTACK_STIX2.json) files into your Threat Intelligence Platforms (TIPs) such as TidalCyber, OpenCTI, MISP, etc.
   - **Benefit**: Integrating these files into your TIPs allows for enhanced threat intelligence analysis and pivoting. It also enables you to see how the user-defined mitigation scores are upgraded when ASR rules are applied, providing a clear view of the improvements in your security posture.

## Author:
Linkedin : [Nounou Mbeiri](https://www.linkedin.com/in/nounou-mbeiri) \
Twitter : [@Nounou Mbeiri](https://twitter.com/Nounou_Mbeiri)
