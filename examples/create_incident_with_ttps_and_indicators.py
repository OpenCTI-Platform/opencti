# coding: utf-8

import datetime
from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

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
    filters=[{"key": "external_id", "values": ["T1193"]}]
)
ttp1_relation = opencti_api_client.stix_relation.create(
    fromType="Incident",
    fromId=incident["id"],
    toType="Attack-Pattern",
    toId=ttp1["id"],
    relationship_type="uses",
    description="We saw the attacker use Spearphishing Attachment.",
    first_seen=date,
    last_seen=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp1["killChainPhasesIds"]:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp1_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )

# Create the observable and indicator and indicates to the relation
# Create the observable
observable_ttp1 = opencti_api_client.stix_observable.create(
    type="Email-Address", observable_value="phishing@mail.com", createIndicator=True
)
# Get the indicator
indicator_ttp1 = observable_ttp1["indicators"][0]
# Indicates the relation Incident => uses => TTP
indicator_ttp1_relation = opencti_api_client.stix_relation.create(
    fromType="Indicator",
    fromId=indicator_ttp1["id"],
    toType="stix_relation",
    toId=ttp1_relation["id"],
    relationship_type="indicates",
    description="This email address is the sender of the spearphishing.",
    first_seen=date,
    last_seen=date,
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
    filters=[{"key": "external_id", "values": ["T1060"]}]
)
# Create the relation
ttp2_relation = opencti_api_client.stix_relation.create(
    fromType="Incident",
    fromId=incident["id"],
    toType="Attack-Pattern",
    toId=ttp2["id"],
    relationship_type="uses",
    description="We saw the attacker use Registry Run Keys / Startup Folder.",
    first_seen=date,
    last_seen=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp2["killChainPhasesIds"]:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp2_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )

# Create the observable and indicator and indicates to the relation
# Create the observable
observable_ttp2 = opencti_api_client.stix_observable.create(
    type="Registry-Key", observable_value="Disk security", createIndicator=True
)
# Get the indicator
indicator_ttp2 = observable_ttp2["indicators"][0]
# Indicates the relation Incident => uses => TTP
indicator_ttp2_relation = opencti_api_client.stix_relation.create(
    fromType="Indicator",
    fromId=indicator_ttp2["id"],
    toType="stix_relation",
    toId=ttp2_relation["id"],
    relationship_type="indicates",
    description="This registry key is used for persistence of tools.",
    first_seen=date,
    last_seen=date,
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
    filters=[{"key": "external_id", "values": ["T1022"]}]
)
ttp3_relation = opencti_api_client.stix_relation.create(
    fromType="Incident",
    fromId=incident["id"],
    toType="Attack-Pattern",
    toId=ttp3["id"],
    relationship_type="uses",
    description="We saw the attacker use Data Encrypted.",
    first_seen=date,
    last_seen=date,
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp3["killChainPhasesIds"]:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp3_relation["id"], kill_chain_phase_id=kill_chain_phase_id
    )
# Elements for the report
object_refs.extend([ttp3["id"], ttp3_relation["id"]])

# Add all element to the report
for object_ref in object_refs:
    opencti_api_client.report.add_stix_entity(
        id=report["id"], report=report, entity_id=object_ref
    )
for observable_ref in observable_refs:
    opencti_api_client.report.add_stix_observable(
        id=report["id"], report=report, stix_observable_id=observable_ref
    )
    opencti_api_client.stix_relation.create(
        fromType="Stix-Observable",
        fromId=observable_ref,
        toType="Incident",
        toId=incident["id"],
        relationship_type="related-to",
        description="This observable is related to the incident.",
        first_seen=date,
        last_seen=date,
    )
