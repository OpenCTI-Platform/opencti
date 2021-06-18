# coding: utf-8

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

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

# Spearphishing Attachment
ttp1 = opencti_api_client.attack_pattern.read(
    filters=[{"key": "x_mitre_id", "values": ["T1193"]}]
)
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

# Registry Run Keys / Startup Folder
ttp2 = opencti_api_client.attack_pattern.read(
    filters=[{"key": "x_mitre_id", "values": ["T1060"]}]
)
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

# Data Encrypted
ttp3 = opencti_api_client.attack_pattern.read(
    filters=[{"key": "x_mitre_id", "values": ["T1022"]}]
)
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
