"""Technology signatures scanned for in job posts, snippets, headers and document metadata.

Patterns are case sensitive on purpose so short acronyms don't match ordinary words.
Add rows freely, the tech plugins pick them up.
"""
import re

SIGNATURES = [
    # Mainframe and midrange
    ("IBM i (AS/400)", r"\b(?:AS/?400|iSeries|IBM i|System i|i5/OS|OS/400)\b"),
    ("z/OS mainframe", r"\bz/OS\b|\b[Mm]ainframe\b"),
    ("z/TPF", r"\bz/?TPF\b|\bTPF\b"),
    ("RACF", r"\bRACF\b"),
    ("CICS", r"\bCICS\b"),
    ("IBM Db2", r"\bDb2\b|\bDB2\b"),
    ("TN3270 and 3270 emulation", r"\bTN3270\b|\b3270\b"),
    ("COBOL", r"\bCOBOL\b"),
    ("Linux on Z (zLinux)", r"\bzLinux\b|Linux on Z|LinuxONE"),
    # Industrial control
    ("Siemens SIMATIC and S7", r"\bSIMATIC\b|\bS7-(?:300|400|1200|1500)\b|\bTIA Portal\b"),
    ("Rockwell and Allen-Bradley", r"Allen[- ]Bradley|\bRockwell\b|FactoryTalk|ControlLogix|CompactLogix|RSLogix|Studio 5000"),
    ("Schneider Electric and Modicon", r"\bModicon\b|\bSchneider Electric\b|EcoStruxure"),
    ("Emerson and GE PLC", r"\bPACSystems\b|\bDeltaV\b|\bEmerson\b"),
    ("SCADA and HMI", r"\bSCADA\b|\bHMI\b"),
    ("Modbus, DNP3, OPC", r"\bModbus\b|\bDNP3\b|\bOPC[- ]?UA\b|\bOPC DA\b"),
    ("Ignition (Inductive Automation)", r"Ignition SCADA|Inductive Automation"),
    ("AVEVA and Wonderware", r"\bAVEVA\b|Wonderware"),
    # Enterprise
    ("Citrix", r"\bCitrix\b|NetScaler"),
    ("VMware", r"\bVMware\b|\bvSphere\b|\bESXi\b"),
    ("Active Directory", r"\bActive Directory\b"),
    ("Microsoft Entra and Azure AD", r"\bEntra\b|\bAzure AD\b"),
    ("Okta", r"\bOkta\b"),
    ("Microsoft Azure", r"\bAzure\b"),
    ("AWS", r"\bAWS\b|Amazon Web Services"),
    ("Google Cloud", r"\bGCP\b|Google Cloud"),
    ("Palo Alto Networks", r"Palo Alto|\bPAN-OS\b|GlobalProtect"),
    ("Fortinet", r"\bFortinet\b|\bFortiGate\b"),
    ("Cisco", r"\bCisco\b"),
    ("Splunk", r"\bSplunk\b"),
    ("ServiceNow", r"\bServiceNow\b"),
    ("SAP", r"\bSAP\b"),
    ("Oracle", r"\bOracle\b"),
    ("Kubernetes and Docker", r"\bKubernetes\b|\bDocker\b"),
    ("Red Hat and RHEL", r"\bRHEL\b|Red Hat"),
    ("Legacy Windows", r"Windows Server 20(?:03|08|12)\b|Windows (?:XP|7)\b"),
]

COMPILED = [(name, re.compile(pat)) for name, pat in SIGNATURES]


def scan(text):
    """Yield (name, match) for every signature found in text."""
    for name, rx in COMPILED:
        m = rx.search(text or "")
        if m:
            yield name, m
