# coding: utf-8

import datetime
from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = 'eef2655c-5727-44db-8219-72bc9a3f2db5'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Define the date
date = parse('2019-12-01').strftime('%Y-%m-%dT%H:%M:%SZ')

# Create the incident
incident = opencti_api_client.incident.create(
    name="My new incident",
    description="We have been compromised",
    objective="Espionage"
)
print(incident)

# Create the associated report
report = opencti_api_client.report.create(
    name="Report about my new incident",
    description="Forensics and investigation report",
    published=date,
    report_class="Internal Report"
)
print(report)

# Prepare all the elements of the report
object_refs = []

# Associate the TTPs to the incident

# Spearphishing Attachment
ttp1 = opencti_api_client.attack_pattern.read(filters=[{'key': 'external_id', 'values': ['T1193']}])
print(ttp1)
ttp1_relation = opencti_api_client.stix_relation.create(
    fromType='Incident',
    fromId=incident['id'],
    toType='Incident',
    toId=ttp1['id'],
    relationship_type='uses',
    description='We saw the attacker use Spearphishing Attachment.',
    first_seen=date,
    last_seen=date
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp1['killChainPhasesIds']:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp1_relation['id'],
        kill_chain_phase_id=kill_chain_phase_id
    )
# Add observables to the relation
observable_ttp1 = opencti_api_client.stix_observable.create(
    type='Email-Addr',
    observable_value='phishing@mail.com'
)
observable_ttp1_relation = opencti_api_client.stix_relation.create(
    fromType='Stix-Observable',
    fromId=observable_ttp1['id'],
    toType='stix_relation',
    toId=ttp1_relation['id'],
    relationship_type='indicates',
    description='This email address is the sender of the spearphishing.',
    first_seen=date,
    last_seen=date
)
# Elements for the report
object_refs.extend([ttp1['id'], ttp1_relation['id'], observable_ttp1['id'], observable_ttp1_relation['id']])

# Registry Run Keys / Startup Folder
ttp2 = opencti_api_client.attack_pattern.read(filters=[{'key': 'external_id', 'values': ['T1060']}])
print(ttp2)
# Create the relation
ttp2_relation = opencti_api_client.stix_relation.create(
    fromType='Incident',
    fromId=incident['id'],
    toType='Incident',
    toId=ttp2['id'],
    relationship_type='uses',
    description='We saw the attacker use Registry Run Keys / Startup Folder.',
    first_seen=date,
    last_seen=date
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp2['killChainPhasesIds']:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp2_relation['id'],
        kill_chain_phase_id=kill_chain_phase_id
    )
# Add observables to the relation
observable_ttp2 = opencti_api_client.stix_observable.create(
    type='Registry-Key',
    observable_value='Disk security'
)
observable_ttp2_relation = opencti_api_client.stix_relation.create(
    fromType='Stix-Observable',
    fromId=observable_ttp2['id'],
    toType='stix_relation',
    toId=ttp2_relation['id'],
    relationship_type='indicates',
    description='This registry key is used for persistence of tools.',
    first_seen=date,
    last_seen=date
)
# Elements for the report
object_refs.extend([ttp2['id'], ttp2_relation['id'], observable_ttp2['id'], observable_ttp2_relation['id']])

# Data Encrypted
ttp3 = opencti_api_client.attack_pattern.read(filters=[{'key': 'external_id', 'values': ['T1022']}])
print(ttp3)
ttp3_relation = opencti_api_client.stix_relation.create(
    fromType='Incident',
    fromId=incident['id'],
    toType='Incident',
    toId=ttp3['id'],
    relationship_type='uses',
    description='We saw the attacker use Data Encrypted.',
    first_seen=date,
    last_seen=date
)
# Add kill chain phases to the relation
for kill_chain_phase_id in ttp3['killChainPhasesIds']:
    opencti_api_client.stix_relation.add_kill_chain_phase(
        id=ttp3_relation['id'],
        kill_chain_phase_id=kill_chain_phase_id
    )
# Elements for the report
object_refs.extend([ttp3['id'], ttp3_relation['id']])

# Add all element to the report
for object_ref in object_refs:
    opencti_api_client.report.add_stix_entity(id=report['id'], report=report, entity_id=object_ref)
