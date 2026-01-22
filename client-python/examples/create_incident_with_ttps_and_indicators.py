# coding: utf-8
import os

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

# Prepare all the elements of the report
object_refs = []
observable_refs = []

# Create the incident
incident = opencti_api_client.incident.create(
    name="My new incident",
    description="We have been compromised",
    objective="Espionage",
)
object_refs.append(incident["id"])
# Create the associated report
report = opencti_api_client.report.create(
    name="Report about my new incident",
    description="Forensics and investigation report",
    published=date,
    report_class="Internal Report",
)

# Associate the TTPs to the incident

kcp_ia = opencti_api_client.kill_chain_phase.create(
    phase_name="initial-access", kill_chain_name="mitre-attack"
)

ttp1 = opencti_api_client.attack_pattern.create(
    name="Phishing: Spearphishing Attachment",
    description="Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.",
    x_mitre_id="T1566.001",
    killChainPhases=[kcp_ia["id"]],
)
ttp1 = opencti_api_client.attack_pattern.read(id=ttp1["id"])
ttp1_relation = opencti_api_client.stix_core_relationship.create(
    fromId=incident["id"],
    toId=ttp1["id"],
    relationship_type="uses",
    description="We saw the attacker use Spearphishing Attachment.",
    start_time=date,
    stop_time=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp1["killChainPhasesIds"]:
    opencti_api_client.stix_core_relationship.add_kill_chain_phase(
        id=ttp1_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )

# Create the observable and indicator and indicates to the relation
# Create the observable
observable_ttp1 = opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="Email-Addr.value",
    simple_observable_value="phishing@mail.com",
    createIndicator=True,
)
# Get the indicator
indicator_ttp1 = observable_ttp1["indicators"][0]
# Indicates the relation Incident => uses => TTP
indicator_ttp1_relation = opencti_api_client.stix_core_relationship.create(
    fromId=indicator_ttp1["id"],
    toId=ttp1_relation["id"],
    relationship_type="indicates",
    description="This email address is the sender of the spearphishing.",
    start_time=date,
    stop_time=date,
)

# Prepare elements for the report
object_refs.extend(
    [
        ttp1["id"],
        ttp1_relation["id"],
        indicator_ttp1["id"],
        indicator_ttp1_relation["id"],
    ]
)
observable_refs.append(observable_ttp1["id"])

kcp_p = opencti_api_client.kill_chain_phase.create(
    phase_name="persistence", kill_chain_name="mitre-attack"
)
kcp_pe = opencti_api_client.kill_chain_phase.create(
    phase_name="privilege-escalation", kill_chain_name="mitre-attack"
)

# Registry Run Keys / Startup Folder
ttp2 = opencti_api_client.attack_pattern.create(
    name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ",
    description="Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the 'run keys' in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.",
    x_mitre_id="T1547.001",
    killChainPhases=[kcp_pe["id"], kcp_p["id"]],
)
ttp2 = opencti_api_client.attack_pattern.read(id=ttp2["id"])
# Create the relation
ttp2_relation = opencti_api_client.stix_core_relationship.create(
    fromId=incident["id"],
    toId=ttp2["id"],
    relationship_type="uses",
    description="We saw the attacker use Registry Run Keys / Startup Folder.",
    start_time=date,
    stop_time=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp2["killChainPhasesIds"]:
    opencti_api_client.stix_core_relationship.add_kill_chain_phase(
        id=ttp2_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )

# Create the observable and indicator and indicates to the relation
# Create the observable
observable_ttp2 = opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="Windows-Registry-Key.key",
    simple_observable_value="HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    createIndicator=True,
)
# Get the indicator
indicator_ttp2 = observable_ttp2["indicators"][0]
# Indicates the relation Incident => uses => TTP
indicator_ttp2_relation = opencti_api_client.stix_core_relationship.create(
    fromId=indicator_ttp2["id"],
    toId=ttp2_relation["id"],
    relationship_type="indicates",
    description="This registry key is used for persistence of tools.",
    start_time=date,
    stop_time=date,
)
# Elements for the report
object_refs.extend(
    [
        ttp2["id"],
        ttp2_relation["id"],
        indicator_ttp2["id"],
        indicator_ttp2_relation["id"],
    ]
)
observable_refs.append(observable_ttp2["id"])

kcp_c = opencti_api_client.kill_chain_phase.create(
    phase_name="collection", kill_chain_name="mitre-attack"
)
# Data Encrypted
ttp3 = opencti_api_client.attack_pattern.create(
    name=" Archive Collected Data",
    description="An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.",
    x_mitre_id="T1560",
    killChainPhases=[kcp_c["id"]],
)
ttp3 = opencti_api_client.attack_pattern.read(id=ttp3["id"])
ttp3_relation = opencti_api_client.stix_core_relationship.create(
    fromId=incident["id"],
    toId=ttp3["id"],
    relationship_type="uses",
    description="We saw the attacker use Data Encrypted.",
    start_time=date,
    stop_time=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp3["killChainPhasesIds"]:
    opencti_api_client.stix_core_relationship.add_kill_chain_phase(
        id=ttp3_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )
# Elements for the report
object_refs.extend([ttp3["id"], ttp3_relation["id"]])

# Add all element to the report
for object_ref in object_refs:
    opencti_api_client.report.add_stix_object_or_stix_relationship(
        id=report["id"], stixObjectOrStixRelationshipId=object_ref
    )
for observable_ref in observable_refs:
    opencti_api_client.report.add_stix_object_or_stix_relationship(
        id=report["id"], stixObjectOrStixRelationshipId=observable_ref
    )
    opencti_api_client.stix_core_relationship.create(
        fromId=observable_ref,
        toId=incident["id"],
        relationship_type="related-to",
        description="This observable is related to the incident.",
        start_time=date,
        stop_time=date,
    )
