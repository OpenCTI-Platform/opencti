# coding: utf-8

import time
import os
import json
import uuid
import datetime
from typing import List

import datefinder
import dateutil.parser
import pytz

import stix2
from stix2 import ObjectPath, ObservationExpression, EqualityComparisonExpression, HashConstant
from pycti.utils.constants import ObservableTypes, CustomProperties

datefinder.ValueError = ValueError, OverflowError
utc = pytz.UTC

# TODO: update this mapping with all the known OpenCTI types
#       the ones below were taken from the misp connector
STIX2OPENCTI = {
    'file:hashes.md5': ObservableTypes.FILE_HASH_MD5.value,
    'file:hashes.sha1': ObservableTypes.FILE_HASH_SHA1.value,
    'file:hashes.sha256': ObservableTypes.FILE_HASH_SHA256.value,
    'ipv4-addr:value': ObservableTypes.IPV4_ADDR.value,
    'domain:value': ObservableTypes.DOMAIN.value,
    'url:value': ObservableTypes.URL.value,
}


class OpenCTIStix2:
    """
        Python API for Stix2 in OpenCTI
        :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.mapping_cache = {}

    def unknown_type(self, stix_object):
        self.opencti.log('error', 'Unknown object type "' + stix_object['type'] + '", doing nothing...')

    def convert_markdown(self, text):
        return text. \
            replace('<code>', '`'). \
            replace('</code>', '`')

    def format_date(self, date):
        if isinstance(date, datetime.date):
            return date.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        if date is not None:
            return dateutil.parser.parse(date).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        else:
            return datetime.datetime.utcnow().isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    def filter_objects(self, uuids, objects):
        result = []
        if objects is not None:
            for object in objects:
                if 'id' in object and object['id'] not in uuids:
                    result.append(object)
        return result

    def pick_aliases(self, stix_object):
        # Add aliases
        if CustomProperties.ALIASES in stix_object:
            return stix_object[CustomProperties.ALIASES]
        elif 'x_mitre_aliases' in stix_object:
            return stix_object['x_mitre_aliases']
        elif 'aliases' in stix_object:
            return stix_object['aliases']
        return None

    def check_max_marking_definition(self, max_marking_definition_entity, entity_marking_definitions):
        # Max is not set, return True
        if max_marking_definition_entity is None:
            return True
        # Filter entity markings definition to the max_marking_definition type
        typed_entity_marking_definitions = []
        for entity_marking_definition in entity_marking_definitions:
            if entity_marking_definition['definition_type'] == max_marking_definition_entity['definition_type']:
                typed_entity_marking_definitions.append(entity_marking_definition)
        # No entity marking defintions of the max_marking_definition type
        if len(typed_entity_marking_definitions) == 0:
            return True

        # Check if level is less or equal to max
        for typed_entity_marking_definition in typed_entity_marking_definitions:
            if typed_entity_marking_definition['level'] <= max_marking_definition_entity['level']:
                return True
        return False

    def import_bundle_from_file(self, file_path, update=False, types=None):
        if types is None:
            types = []
        if not os.path.isfile(file_path):
            self.opencti.log('error', 'The bundle file does not exists')
            return None

        with open(os.path.join(file_path)) as file:
            data = json.load(file)

        return self.import_bundle(data, update, types)

    def import_bundle_from_json(self, json_data, update=False, types=None) -> List:
        if types is None:
            types = []
        data = json.loads(json_data)
        return self.import_bundle(data, update, types)

    def extract_embedded_relationships(self, stix_object, types=None):
        # Created By Ref
        created_by_ref_id = None
        if 'created_by_ref' in stix_object:
            created_by_ref = stix_object['created_by_ref']
            if created_by_ref in self.mapping_cache:
                created_by_ref_result = self.mapping_cache[created_by_ref]
            else:
                created_by_ref_result = self.opencti.stix_domain_entity.read(id=created_by_ref)
            if created_by_ref_result is not None:
                self.mapping_cache[created_by_ref] = {'id': created_by_ref_result['id']}
                created_by_ref_id = created_by_ref_result['id']

        # Object Marking Refs
        marking_definitions_ids = []
        if 'object_marking_refs' in stix_object:
            for object_marking_ref in stix_object['object_marking_refs']:
                if object_marking_ref in self.mapping_cache:
                    object_marking_ref_result = self.mapping_cache[object_marking_ref]
                else:
                    object_marking_ref_result = self.opencti.marking_definition.read(id=object_marking_ref)
                if object_marking_ref_result is not None:
                    self.mapping_cache[object_marking_ref] = {'id': object_marking_ref_result['id']}
                    marking_definitions_ids.append(object_marking_ref_result['id'])

        # TODO Import tags
        # Object Tags
        tags_ids = []
        # if CustomProperties.TAG_TYPE in stix_object:
        #    for tag in stix_object[CustomProperties.TAG_TYPE]:
        #        if tag['id'] in self.mapping_cache:
        #            tag_result = self.mapping_cache[tag['id']]
        #        else:
        #            object_marking_ref_result = self.opencti.tag.read(id=object_marking_ref)
        #        if object_marking_ref_result is not None:
        #           self.mapping_cache[object_marking_ref] = {'id': object_marking_ref_result['id']}
        #           marking_definitions_ids.append(object_marking_ref_result['id'])

        # Kill Chain Phases
        kill_chain_phases_ids = []
        if 'kill_chain_phases' in stix_object:
            for kill_chain_phase in stix_object['kill_chain_phases']:
                if kill_chain_phase['phase_name'] in self.mapping_cache:
                    kill_chain_phase_id = self.mapping_cache[kill_chain_phase['phase_name']]['id']
                else:
                    kill_chain_phase_id = self.opencti.create_kill_chain_phase_if_not_exists(
                        kill_chain_phase['kill_chain_name'],
                        kill_chain_phase['phase_name'],
                        kill_chain_phase[
                            CustomProperties.PHASE_ORDER] if CustomProperties.PHASE_ORDER in kill_chain_phase else 0,
                        kill_chain_phase[
                            CustomProperties.ID] if CustomProperties.ID in kill_chain_phase else None,
                        kill_chain_phase['id'] if 'id' in kill_chain_phase else None,
                        kill_chain_phase[
                            CustomProperties.CREATED] if CustomProperties.CREATED in kill_chain_phase else None,
                        kill_chain_phase[
                            CustomProperties.MODIFIED] if CustomProperties.MODIFIED in kill_chain_phase else None,
                    )['id']
                self.mapping_cache[kill_chain_phase['phase_name']] = {'id': kill_chain_phase_id}
                kill_chain_phases_ids.append(kill_chain_phase_id)

        # Object refs
        object_refs_ids = []
        if 'object_refs' in stix_object:
            for object_ref in stix_object['object_refs']:
                if object_ref in self.mapping_cache:
                    object_ref_result = self.mapping_cache[object_ref]
                elif 'relationship' in object_ref:
                    object_ref_result = self.opencti.stix_relation.read(stix_id_key=object_ref)
                else:
                    object_ref_result = self.opencti.stix_entity.read(id=object_ref)

                if object_ref_result is not None:
                    self.mapping_cache[object_ref] = {'id': object_ref_result['id']}
                    object_refs_ids.append(object_ref_result['id'])

        # External References
        reports = {}
        external_references_ids = []
        if 'external_references' in stix_object:
            for external_reference in stix_object['external_references']:
                if 'url' in external_reference and 'source_name' in external_reference:
                    url = external_reference['url']
                    source_name = external_reference['source_name']
                else:
                    continue
                if url in self.mapping_cache:
                    external_reference_id = self.mapping_cache[url]['id']
                else:
                    external_reference_id = self.opencti.create_external_reference_if_not_exists(
                        source_name,
                        url,
                        external_reference['external_id'] if 'external_id' in external_reference else None,
                        external_reference['description'] if 'description' in external_reference else None,
                        external_reference['id'] if 'id' in external_reference else None,
                        external_reference[CustomProperties.ID] if CustomProperties.ID in external_reference else None,
                        external_reference[
                            CustomProperties.CREATED] if CustomProperties.CREATED in external_reference else None,
                        external_reference[
                            CustomProperties.MODIFIED] if CustomProperties.MODIFIED in external_reference else None,
                    )['id']
                self.mapping_cache[url] = {'id': external_reference_id}
                external_references_ids.append(external_reference_id)

                if stix_object['type'] in [
                    'threat-actor',
                    'intrusion-set',
                    'campaign',
                    'incident',
                    'malware'
                ] and (types is None or 'report' in types):
                    # Add a corresponding report
                    # Extract date
                    try:
                        if 'description' in external_reference:
                            matches = list(datefinder.find_dates(external_reference['description']))
                        else:
                            matches = list(datefinder.find_dates(source_name))
                    except:
                        matches = []
                    if len(matches) > 0:
                        published = list(matches)[0].strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        published = datetime.datetime.today().strftime('%Y-%m-%dT%H:%M:%SZ')

                    if 'mitre' in source_name and 'name' in stix_object:
                        title = '[MITRE ATT&CK] ' + stix_object['name']
                        if 'modified' in stix_object:
                            published = stix_object['modified']
                    else:
                        title = source_name

                    if 'external_id' in external_reference:
                        title = title + ' (' + external_reference['external_id'] + ')'
                    report = self.opencti.report.create(
                        name=title,
                        external_reference_id=external_reference_id,
                        description=external_reference['description'] if 'description' in external_reference else '',
                        published=published,
                        report_class='Threat Report',
                        object_status=2,
                        update=True
                    )
                    # Resolve author
                    author = self.resolve_author(title)
                    if author is not None:
                        self.opencti.stix_entity.update_created_by_ref(
                            id=report['id'],
                            entity=report,
                            identity_id=author['id']
                        )

                    # Add marking
                    if 'marking_tlpwhite' in self.mapping_cache:
                        object_marking_ref_result = self.mapping_cache['marking_tlpwhite']
                    else:
                        object_marking_ref_result = self.opencti.marking_definition.read(filters=[
                            {'key': 'definition_type', 'values': ['TLP']},
                            {'key': 'definition', 'values': ['TLP:WHITE']}]
                        )
                    if object_marking_ref_result is not None:
                        self.mapping_cache['marking_tlpwhite'] = {'id': object_marking_ref_result['id']}
                        self.opencti.stix_entity.add_marking_definition(
                            id=report['id'],
                            entity=report,
                            marking_definition_id=object_marking_ref_result['id']
                        )

                    # Add external reference to report
                    self.opencti.stix_entity.add_external_reference(
                        id=report['id'],
                        entity=report,
                        external_reference_id=external_reference_id
                    )
                    reports[external_reference_id] = report['id']

        return {
            'created_by_ref': created_by_ref_id,
            'marking_definitions': marking_definitions_ids,
            'kill_chain_phases': kill_chain_phases_ids,
            'object_refs': object_refs_ids,
            'external_references': external_references_ids,
            'reports': reports
        }

    def import_object(self, stix_object, update=False, types=None):
        self.opencti.log('info', 'Importing a ' + stix_object['type'] + ' (id: ' + stix_object['id'] + ')')

        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object, types)
        created_by_ref_id = embedded_relationships['created_by_ref']
        marking_definitions_ids = embedded_relationships['marking_definitions']
        kill_chain_phases_ids = embedded_relationships['kill_chain_phases']
        object_refs_ids = embedded_relationships['object_refs']
        external_references_ids = embedded_relationships['external_references']
        reports = embedded_relationships['reports']

        # Import
        importer = {
            'marking-definition': self.create_marking_definition,
            'identity': self.create_identity,
            'threat-actor': self.create_threat_actor,
            'intrusion-set': self.create_intrusion_set,
            'campaign': self.create_campaign,
            'x-opencti-incident': self.create_incident,
            'malware': self.create_malware,
            'tool': self.create_tool,
            'vulnerability': self.create_vulnerability,
            'attack-pattern': self.create_attack_pattern,
            'course-of-action': self.create_course_of_action,
            'report': self.create_report,
            'indicator': self.create_indicator,
        }
        do_import = importer.get(
            stix_object['type'],
            lambda stix_object, update: self.unknown_type(stix_object)
        )
        stix_object_result = do_import(stix_object, update)

        # Add embedded relationships
        if stix_object_result is not None:
            self.mapping_cache[stix_object['id']] = {'id': stix_object_result['id'], 'type': stix_object_result['entity_type']}

            # Update created by ref
            if created_by_ref_id is not None and stix_object['type'] != 'marking-definition':
                self.opencti.stix_entity.update_created_by_ref(
                    id=stix_object_result['id'],
                    entity=stix_object_result,
                    identity_id=created_by_ref_id
                )
            # Add marking definitions
            for marking_definition_id in marking_definitions_ids:
                self.opencti.stix_entity.add_marking_definition(
                    id=stix_object_result['id'],
                    entity=stix_object_result,
                    marking_definition_id=marking_definition_id
                )
            # Add external references
            for external_reference_id in external_references_ids:
                self.opencti.stix_entity.add_external_reference(
                    id=stix_object_result['id'],
                    entity=stix_object_result,
                    external_reference_id=external_reference_id
                )
                if external_reference_id in reports:
                    self.opencti.report.add_stix_entity(
                        id=reports[external_reference_id],
                        entity_id=stix_object_result['id']
                    )
            # Add kill chain phases
            for kill_chain_phase_id in kill_chain_phases_ids:
                self.opencti.stix_entity.add_kill_chain_phase(
                    id=stix_object_result['id'],
                    entity=stix_object_result,
                    kill_chain_phase_id=kill_chain_phase_id
                )
            # Add object refs
            for object_refs_id in object_refs_ids:
                self.opencti.report.add_stix_entity(
                    id=stix_object_result['id'],
                    report=stix_object_result,
                    entity_id=object_refs_id
                )

        return stix_object_result

    def import_relationship(self, stix_relation, update=False, types=None):
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_relation, types)
        created_by_ref_id = embedded_relationships['created_by_ref']
        marking_definitions_ids = embedded_relationships['marking_definitions']
        kill_chain_phases_ids = embedded_relationships['kill_chain_phases']
        external_references_ids = embedded_relationships['external_references']
        reports = embedded_relationships['reports']

        # Check relation
        stix_relation_result = self.opencti.stix_relation.read(id=stix_relation['id'])
        if stix_relation_result is not None:
            return stix_relation_result

        # Check entities
        if stix_relation['source_ref'] in self.mapping_cache:
            source_id = self.mapping_cache[stix_relation['source_ref']]['id']
            source_type = self.mapping_cache[stix_relation['source_ref']]['type']
        else:
            if CustomProperties.SOURCE_REF in stix_relation:
                stix_object_result = self.opencti.stix_entity.read(id=stix_relation[CustomProperties.SOURCE_REF])
            else:
                stix_object_result = self.opencti.stix_entity.read(id=stix_relation['source_ref'])
            if stix_object_result is not None:
                source_id = stix_object_result['id']
                source_type = stix_object_result['entity_type']
            else:
                self.opencti.log('error', 'Source ref of the relationship not found, doing nothing...')
                return None

        if stix_relation['target_ref'] in self.mapping_cache:
            target_id = self.mapping_cache[stix_relation['target_ref']]['id']
            target_type = self.mapping_cache[stix_relation['target_ref']]['type']
        else:
            if CustomProperties.TARGET_REF in stix_relation:
                stix_object_result = self.opencti.stix_entity.read(id=stix_relation[CustomProperties.TARGET_REF])
            else:
                stix_object_result = self.opencti.stix_entity.read(id=stix_relation['target_ref'])
            if stix_object_result is not None:
                target_id = stix_object_result['id']
                target_type = stix_object_result['entity_type']
            else:
                self.opencti.log('error', 'Target ref of the relationship not found, doing nothing...')
                return None

        date = None
        if 'external_references' in stix_relation:
            for external_reference in stix_relation['external_references']:
                try:
                    if 'description' in external_reference:
                        matches = list(datefinder.find_dates(external_reference['description']))
                    else:
                        matches = list(datefinder.find_dates(external_reference['source_name']))
                except:
                    matches = []
                if len(matches) > 0:
                    date = matches[0].strftime('%Y-%m-%dT%H:%M:%SZ')
                else:
                    date = datetime.datetime.today().strftime('%Y-%m-%dT%H:%M:%SZ')
        if date is None:
            date = datetime.datetime.utcnow().replace(microsecond=0, tzinfo=datetime.timezone.utc).isoformat()

        stix_relation_result = self.opencti.stix_relation.create(
            fromId=source_id,
            fromType=source_type,
            toId=target_id,
            toType=target_type,
            relationship_type=stix_relation['relationship_type'],
            description=self.convert_markdown(stix_relation['description']) if 'description' in stix_relation else None,
            first_seen=stix_relation[
                CustomProperties.FIRST_SEEN] if CustomProperties.FIRST_SEEN in stix_relation else date,
            last_seen=stix_relation[
                CustomProperties.LAST_SEEN] if CustomProperties.LAST_SEEN in stix_relation else date,
            weight=stix_relation[CustomProperties.WEIGHT] if CustomProperties.WEIGHT in stix_relation else 1,
            role_played=stix_relation[
                CustomProperties.ROLE_PLAYED] if CustomProperties.ROLE_PLAYED in stix_relation else None,
            id=stix_relation[CustomProperties.ID] if CustomProperties.ID in stix_relation else None,
            stix_id_key=stix_relation['id'] if 'id' in stix_relation else None,
            created=stix_relation['created'] if 'created' in stix_relation else None,
            modified=stix_relation['modified'] if 'modified' in stix_relation else None,
            update=update,
            ignore_dates=stix_relation[
                CustomProperties.IGNORE_DATES] if CustomProperties.IGNORE_DATES in stix_relation else None,
        )
        if stix_relation_result is not None:
            self.mapping_cache[stix_relation['id']] = {'id': stix_relation_result['id']}
        else:
            return None

        # Update created by ref
        if created_by_ref_id is not None:
            self.opencti.stix_entity.update_created_by_ref(
                id=stix_relation_result['id'],
                entity=stix_relation_result,
                identity_id=created_by_ref_id
            )
        # Add marking definitions
        for marking_definition_id in marking_definitions_ids:
            self.opencti.stix_entity.add_marking_definition(
                id=stix_relation_result['id'],
                entity=stix_relation_result,
                marking_definition_id=marking_definition_id
            )
        # Add external references
        for external_reference_id in external_references_ids:
            self.opencti.stix_entity.add_external_reference(
                id=stix_relation_result['id'],
                entity=stix_relation_result,
                external_reference_id=external_reference_id
            )
            if external_reference_id in reports:
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id],
                    entity_id=stix_relation_result['id']
                )
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id],
                    entity_id=source_id
                )
                self.opencti.report.add_stix_entity(
                    id=reports[external_reference_id],
                    entity_id=target_id
                )
        # Add kill chain phases
        for kill_chain_phase_id in kill_chain_phases_ids:
            self.opencti.stix_entity.add_kill_chain_phase(
                id=stix_relation_result['id'],
                entity=stix_relation_result,
                kill_chain_phase_id=kill_chain_phase_id
            )

    def import_observables(self, stix_object):
        # Extract
        embedded_relationships = self.extract_embedded_relationships(stix_object)
        created_by_ref_id = embedded_relationships['created_by_ref']
        marking_definitions_ids = embedded_relationships['marking_definitions']

        observables_to_create = {}
        relations_to_create = []
        for key, observable_item in stix_object['objects'].items():
            # TODO artifact
            if observable_item['type'] == 'autonomous-system':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'stix_id': 'observable--' + str(uuid.uuid4()),
                    'type': ObservableTypes.AUTONOMOUS_SYSTEM.value,
                    'value': 'AS' + observable_item['number']
                }]
            if observable_item['type'] == 'directory':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'stix_id': 'observable--' + str(uuid.uuid4()),
                    'type': ObservableTypes.DIRECTORY.value,
                    'value': observable_item['path']
                }]
            if observable_item['type'] == 'domain-name':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'stix_id': 'observable--' + str(uuid.uuid4()),
                    'type': ObservableTypes.DOMAIN.value,
                    'value': observable_item['value']
                }]
            if observable_item['type'] == 'email-addr':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'stix_id': 'observable--' + str(uuid.uuid4()),
                    'type': ObservableTypes.EMAIL_ADDR.value,
                    'value': observable_item['value']
                }]
                # TODO Belongs to ref
            # TODO email-message
            # TODO mime-part-type
            if observable_item['type'] == 'file':
                observables_to_create[key] = []
                if 'name' in observable_item:
                    observables_to_create[key].append({
                        'id': str(uuid.uuid4()),
                        'type': ObservableTypes.FILE_NAME.value,
                        'value': observable_item['name']
                    })
                if 'hashes' in observable_item:
                    for keyfile, value in observable_item['hashes'].items():
                        if keyfile == 'MD5':
                            observables_to_create[key].append({
                                'id': str(uuid.uuid4()),
                                'type': ObservableTypes.FILE_HASH_MD5.value,
                                'value': value
                            })
                        if keyfile == 'SHA-1':
                            observables_to_create[key].append({
                                'id': str(uuid.uuid4()),
                                'type': ObservableTypes.FILE_HASH_SHA1.value,
                                'value': value
                            })
                        if keyfile == 'SHA-256':
                            observables_to_create[key].append({
                                'id': str(uuid.uuid4()),
                                'type': ObservableTypes.FILE_HASH_SHA256.value,
                                'value': value
                            })
            if observable_item['type'] == 'ipv4-addr':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'type': ObservableTypes.IPV4_ADDR.value,
                    'value': observable_item['value']
                }]
            if observable_item['type'] == 'ipv6-addr':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'type': ObservableTypes.IPV6_ADDR.value,
                    'value': observable_item['value']
                }]
            if observable_item['type'] == 'mac-addr':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'type': ObservableTypes.MAC_ADDR.value,
                    'value': observable_item['value']
                }]
            if observable_item['type'] == 'windows-registry-key':
                observables_to_create[key] = [{
                    'id': str(uuid.uuid4()),
                    'type': ObservableTypes.REGISTRY_KEY.value,
                    'value': observable_item['key']
                }]

        for key, observable_item in stix_object['objects'].items():
            if observable_item['type'] == 'directory':
                if 'contains_refs' in observable_item:
                    for file in observable_item['contains_refs']:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[file]:
                                if observable_to_create_from['id'] != observables_to_create_to['id']:
                                    relations_to_create.append({
                                        'id': str(uuid.uuid4()),
                                        'from': observable_to_create_from['id'],
                                        'to': observables_to_create_to['id'],
                                        'type': 'contains'}
                                    )
            if observable_item['type'] == 'domain-name':
                if 'resolves_to_refs' in observable_item:
                    for resolved in observable_item['resolves_to_refs']:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[resolved]:
                                if observable_to_create_from['id'] != observables_to_create_to['id']:
                                    relations_to_create.append({
                                        'id': str(uuid.uuid4()),
                                        'from': observable_to_create_from['id'],
                                        'fromType': observable_to_create_from['type'],
                                        'to': observables_to_create_to['id'],
                                        'toType': observables_to_create_to['type'],
                                        'type': 'resolves'}
                                    )
            if observable_item['type'] == 'file':
                for observable_to_create_from in observables_to_create[key]:
                    for observables_to_create_to in observables_to_create[key]:
                        if observable_to_create_from['id'] != observables_to_create_to['id']:
                            relations_to_create.append({
                                'id': str(uuid.uuid4()),
                                'from': observable_to_create_from['id'],
                                'fromType': observable_to_create_from['type'],
                                'to': observables_to_create_to['id'],
                                'toType': observables_to_create_to['type'],
                                'type': 'corresponds'}
                            )
            if observable_item['type'] == 'ipv4-addr':
                if 'belongs_to_refs' in observable_item:
                    for belonging in observable_item['belongs_to_refs']:
                        for observable_to_create_from in observables_to_create[key]:
                            for observables_to_create_to in observables_to_create[belonging]:
                                if observable_to_create_from['id'] != observables_to_create_to['id']:
                                    relations_to_create.append({
                                        'id': str(uuid.uuid4()),
                                        'from': observable_to_create_from['id'],
                                        'fromType': observable_to_create_from['type'],
                                        'to': observables_to_create_to['id'],
                                        'toType': observables_to_create_to['type'],
                                        'type': 'belongs'}
                                    )

        stix_observables_mapping = {}
        for key, observable_to_create in observables_to_create.items():
            for observable in observable_to_create:
                observable_result = self.opencti.stix_observable.create(
                    type=observable['type'],
                    observable_value=observable['value'],
                    id=observable['id'],
                )
                stix_observables_mapping[observable['id']] = observable_result['id']

        stix_observable_relations_mapping = {}
        for relation_to_create in relations_to_create:
            stix_observable_relation_result = self.opencti.stix_observable_relation.create(
                fromId=stix_observables_mapping[relation_to_create['from']],
                fromType=relation_to_create['fromType'],
                toId=stix_observables_mapping[relation_to_create['to']],
                toType=relation_to_create['toType'],
                relationship_type=relation_to_create['type']
            )
            stix_observable_relations_mapping[relation_to_create['id']] = stix_observable_relation_result['id']

        for key, stix_observable_id in stix_observables_mapping.items():
            # Update created by ref
            if created_by_ref_id is not None:
                self.opencti.stix_entity.update_created_by_ref(
                    id=stix_observable_id,
                    identity_id=created_by_ref_id
                )
            # Add marking definitions
            for marking_definition_id in marking_definitions_ids:
                self.opencti.stix_entity.add_marking_definition(
                    id=stix_observable_id,
                    marking_definition_id=marking_definition_id
                )

        for key, stix_observable_relation_id in stix_observable_relations_mapping.items():
            # Update created by ref
            if created_by_ref_id is not None:
                self.opencti.stix_entity.update_created_by_ref(
                    id=stix_observable_relation_id,
                    identity_id=created_by_ref_id
                )
            # Add marking definitions
            for marking_definition_id in marking_definitions_ids:
                self.opencti.stix_entity.add_marking_definition(
                    id=stix_observable_relation_id,
                    marking_definition_id=marking_definition_id
                )

    def export_entity(self, entity_type, entity_id, mode='simple', max_marking_definition=None):
        max_marking_definition_entity = self.opencti.get_marking_definition_by_id(
            max_marking_definition) if max_marking_definition is not None else None
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': []
        }
        # Export
        exporter = {
            'identity': self.opencti.identity.to_stix2,
            'threat-actor': self.opencti.threat_actor.to_stix2,
            'intrusion-set': self.opencti.intrusion_set.to_stix2,
            'campaign': self.opencti.campaign.to_stix2,
            'incident': self.opencti.incident.to_stix2,
            'malware': self.opencti.malware.to_stix2,
            'tool': self.opencti.tool.to_stix2,
            'vulnerability': self.opencti.vulnerability.to_stix2,
            'attack-pattern': self.opencti.attack_pattern.to_stix2,
            'course-of-action': self.opencti.course_of_action.to_stix2,
            'report': self.opencti.report.to_stix2
        }
        do_export = exporter.get(
            entity_type,
            lambda **kwargs: self.unknown_type({'type': entity_type})
        )
        objects = do_export(
            id=entity_id,
            mode=mode,
            max_marking_definition_entity=max_marking_definition_entity
        )
        for object in objects:
            object['id'] = object['id'].replace('observable', 'indicator')
            if 'source_ref' in object:
                object['source_ref'] = object['source_ref'].replace('observable', 'indicator')
            if 'target_ref' in object:
                object['target_ref'] = object['target_ref'].replace('observable', 'indicator')
            bundle['objects'].append(object)

        return bundle

    def export_bundle(self, types=[]):
        uuids = []
        bundle = {
            'type': 'bundle',
            'id': 'bundle--' + str(uuid.uuid4()),
            'spec_version': '2.0',
            'objects': []
        }
        if 'Identity' in types:
            identities = self.opencti.get_identities()
            for identity in identities:
                if identity['entity_type'] != 'threat-actor':
                    identity_bundle = self.filter_objects(uuids, self.opencti.identity.to_stix2(entity=identity))
                    uuids = uuids + [x['id'] for x in identity_bundle]
                    bundle['objects'] = bundle['objects'] + identity_bundle
        if 'Threat-Actor' in types:
            threat_actors = self.opencti.get_threat_actors()
            for threat_actor in threat_actors:
                threat_actor_bundle = self.filter_objects(uuids,
                                                          self.opencti.threat_actor.to_stix2(entity=threat_actor))
                uuids = uuids + [x['id'] for x in threat_actor_bundle]
                bundle['objects'] = bundle['objects'] + threat_actor_bundle
        if 'Intrusion-Set' in types:
            intrusion_sets = self.opencti.get_intrusion_sets()
            for intrusion_set in intrusion_sets:
                intrusion_set_bundle = self.opencti.filter_objects(uuids, self.opencti.intrusion_set.to_stix2(
                    entity=intrusion_set))
                uuids = uuids + [x['id'] for x in intrusion_set_bundle]
                bundle['objects'] = bundle['objects'] + intrusion_set_bundle
        if 'Campaign' in types:
            campaigns = self.opencti.get_campaigns()
            for campaign in campaigns:
                campaign_bundle = self.filter_objects(uuids, self.opencti.campaign.to_stix2(entity=campaign))
                uuids = uuids + [x['id'] for x in campaign_bundle]
                bundle['objects'] = bundle['objects'] + campaign_bundle
        if 'Incident' in types:
            incidents = self.opencti.get_incidents()
            for incident in incidents:
                incident_bundle = self.filter_objects(uuids, self.opencti.incident.to_stix2(entity=incident))
                uuids = uuids + [x['id'] for x in incident_bundle]
                bundle['objects'] = bundle['objects'] + incident_bundle
        if 'Malware' in types:
            malwares = self.opencti.get_malwares()
            for malware in malwares:
                malware_bundle = self.filter_objects(uuids, self.opencti.malware.to_stix2(entity=malware))
                uuids = uuids + [x['id'] for x in malware_bundle]
                bundle['objects'] = bundle['objects'] + malware_bundle
        if 'Tool' in types:
            tools = self.opencti.get_tools()
            for tool in tools:
                tool_bundle = self.filter_objects(uuids, self.opencti.tool.to_stix2(entity=tool))
                uuids = uuids + [x['id'] for x in tool_bundle]
                bundle['objects'] = bundle['objects'] + tool_bundle
        if 'Vulnerability' in types:
            vulnerabilities = self.opencti.get_vulnerabilities()
            for vulnerability in vulnerabilities:
                vulnerability_bundle = self.filter_objects(uuids,
                                                           self.opencti.vulnerability.to_stix2(entity=vulnerability))
                uuids = uuids + [x['id'] for x in vulnerability_bundle]
                bundle['objects'] = bundle['objects'] + vulnerability_bundle
        if 'Attack-Pattern' in types:
            attack_patterns = self.opencti.get_attack_patterns()
            for attack_pattern in attack_patterns:
                attack_pattern_bundle = self.filter_objects(uuids,
                                                            self.opencti.attack_pattern.to_stix2(entity=attack_pattern))
                uuids = uuids + [x['id'] for x in attack_pattern_bundle]
                bundle['objects'] = bundle['objects'] + attack_pattern_bundle
        if 'Course-Of-Action' in types:
            course_of_actions = self.opencti.get_course_of_actions()
            for course_of_action in course_of_actions:
                course_of_action_bundle = self.filter_objects(uuids, self.opencti.course_of_action.to_stix2(
                    entity=course_of_action))
                uuids = uuids + [x['id'] for x in course_of_action_bundle]
                bundle['objects'] = bundle['objects'] + course_of_action_bundle
        if 'Report' in types:
            reports = self.opencti.get_reports()
            for report in reports:
                report_bundle = self.filter_objects(uuids, self.opencti.report.to_stix2(entity=report))
                uuids = uuids + [x['id'] for x in report_bundle]
                bundle['objects'] = bundle['objects'] + report_bundle
        if 'Relationship' in types:
            stix_relations = self.opencti.get_stix_relations()
            for stix_relation in stix_relations:
                stix_relation_bundle = self.filter_objects(uuids,
                                                           self.opencti.stix_relation.to_stix2(entity=stix_relation))
                uuids = uuids + [x['id'] for x in stix_relation_bundle]
                bundle['objects'] = bundle['objects'] + stix_relation_bundle
        return bundle

    def prepare_export(self, entity, stix_object, mode='simple', max_marking_definition_entity=None):
        if self.check_max_marking_definition(max_marking_definition_entity, entity['markingDefinitions']) is False:
            self.opencti.log('info', 'Marking definitions of ' + stix_object['type'] + ' "' + stix_object[
                'name'] + '" are less than max definition, not exporting.')
            return []
        result = []
        objects_to_get = []
        observables_to_get = []
        relations_to_get = []
        if 'createdByRef' in entity and entity['createdByRef'] is not None:
            entity_created_by_ref = entity['createdByRef']
            if entity_created_by_ref['entity_type'] == 'user':
                identity_class = 'individual'
            elif entity_created_by_ref['entity_type'] == 'sector':
                identity_class = 'class'
            else:
                identity_class = entity_created_by_ref['entity_type']

            created_by_ref = dict()
            created_by_ref['id'] = entity_created_by_ref['stix_id_key']
            created_by_ref['type'] = 'identity'
            created_by_ref['name'] = entity_created_by_ref['name']
            created_by_ref['identity_class'] = identity_class
            if self.opencti.not_empty(entity_created_by_ref['stix_label']):
                created_by_ref['labels'] = entity_created_by_ref['stix_label']
            else:
                created_by_ref['labels'] = ['identity']
            created_by_ref['created'] = self.format_date(entity_created_by_ref['created'])
            created_by_ref['modified'] = self.format_date(entity_created_by_ref['modified'])
            if self.opencti.not_empty(entity_created_by_ref['alias']):
                created_by_ref[CustomProperties.ALIASES] = entity_created_by_ref['alias']
            created_by_ref[CustomProperties.IDENTITY_TYPE] = entity_created_by_ref['entity_type']
            created_by_ref[CustomProperties.ID] = entity_created_by_ref['id']

            stix_object['created_by_ref'] = created_by_ref['id']
            result.append(created_by_ref)
        if 'markingDefinitions' in entity and len(entity['markingDefinitions']) > 0:
            marking_definitions = []
            for entity_marking_definition in entity['markingDefinitions']:
                marking_definition = {
                    'id': entity_marking_definition['stix_id_key'],
                    'type': 'marking-definition',
                    'definition_type': entity_marking_definition['definition_type'],
                    'definition': {
                        entity_marking_definition['definition_type']: entity_marking_definition['definition']
                    },
                    'created': entity_marking_definition['created'],
                    CustomProperties.MODIFIED: entity_marking_definition['modified'],
                    CustomProperties.ID: entity_marking_definition['id']
                }
                marking_definitions.append(marking_definition['id'])
                result.append(marking_definition)
            stix_object['object_marking_refs'] = marking_definitions
        if 'tags' in entity and len(entity['tags']) > 0:
            tags = []
            for entity_tag in entity['tags']:
                tag = {
                    'id': entity_tag['id'],
                    'tag_type': entity_tag['tag_type'],
                    'value': entity_tag['value'],
                    'color': entity_tag['color']
                }
                tags.append(tag)
            stix_object[CustomProperties.TAG_TYPE] = tags
        if 'killChainPhases' in entity and len(entity['killChainPhases']) > 0:
            kill_chain_phases = []
            for entity_kill_chain_phase in entity['killChainPhases']:
                kill_chain_phase = {
                    'id': entity_kill_chain_phase['stix_id_key'],
                    'kill_chain_name': entity_kill_chain_phase['kill_chain_name'],
                    'phase_name': entity_kill_chain_phase['phase_name'],
                    CustomProperties.ID: entity_kill_chain_phase['id'],
                    CustomProperties.PHASE_ORDER: entity_kill_chain_phase['phase_order'],
                    CustomProperties.CREATED: entity_kill_chain_phase['created'],
                    CustomProperties.MODIFIED: entity_kill_chain_phase['modified'],
                }
                kill_chain_phases.append(kill_chain_phase)
            stix_object['kill_chain_phases'] = kill_chain_phases
        if 'externalReferences' in entity and len(entity['externalReferences']) > 0:
            external_references = []
            for entity_external_reference in entity['externalReferences']:
                external_reference = {
                    'id': entity_external_reference['stix_id_key'],
                    'source_name': entity_external_reference['source_name'],
                    'description': entity_external_reference['description'],
                    'url': entity_external_reference['url'],
                    'hash': entity_external_reference['hash'],
                    'external_id': entity_external_reference['external_id'],
                    CustomProperties.ID: entity_external_reference['id'],
                    CustomProperties.CREATED: entity_external_reference['created'],
                    CustomProperties.MODIFIED: entity_external_reference['modified'],
                }
                external_references.append(external_reference)
            stix_object['external_references'] = external_references
        if 'objectRefs' in entity and len(entity['objectRefs']) > 0:
            object_refs = []
            objects_to_get = entity['objectRefs']
            for entity_object_ref in entity['objectRefs']:
                object_refs.append(entity_object_ref['stix_id_key'])
            if 'observableRefs' in entity and len(entity['observableRefs']) > 0:
                observables_to_get = entity['observableRefs']
                for entity_observable_ref in entity['observableRefs']:
                    if entity_observable_ref['stix_id_key'] not in object_refs:
                        object_refs.append(entity_observable_ref['stix_id_key'])
            if 'relationRefs' in entity and len(entity['relationRefs']) > 0:
                relations_to_get = entity['relationRefs']
                for entity_relation_ref in entity['relationRefs']:
                    if entity_relation_ref['stix_id_key'] not in object_refs:
                        object_refs.append(entity_relation_ref['stix_id_key'])
            stix_object['object_refs'] = object_refs

        result.append(stix_object)
        if mode == 'simple':
            return result
        elif mode == 'full':
            uuids = []
            for x in result:
                uuids.append(x['id'])

            # Get extra relations
            stix_relations = self.opencti.stix_relation.list(fromId=entity['id'])
            for stix_relation in stix_relations:
                if self.check_max_marking_definition(max_marking_definition_entity,
                                                     stix_relation['markingDefinitions']):
                    objects_to_get.append(stix_relation['to'])
                    relation_object_data = self.opencti.stix_relation.to_stix2(entity=stix_relation)
                    relation_object_bundle = self.filter_objects(uuids, relation_object_data)
                    uuids = uuids + [x['id'] for x in relation_object_bundle]
                    result = result + relation_object_bundle
                else:
                    self.opencti.log('info',
                                     'Marking definitions of ' + stix_relation['entity_type'] + ' "' + stix_relation[
                                         'id'] + '" are less than max definition, not exporting the relation AND the target entity.')

            # Export
            exporter = {
                'identity': self.opencti.identity.to_stix2,
                'threat-actor': self.opencti.threat_actor.to_stix2,
                'intrusion-set': self.opencti.intrusion_set.to_stix2,
                'campaign': self.opencti.campaign.to_stix2,
                'incident': self.opencti.incident.to_stix2,
                'malware': self.opencti.malware.to_stix2,
                'tool': self.opencti.tool.to_stix2,
                'vulnerability': self.opencti.vulnerability.to_stix2,
                'attack-pattern': self.opencti.attack_pattern.to_stix2,
                'course-of-action': self.opencti.course_of_action.to_stix2,
                'report': self.opencti.report.to_stix2
            }

            # Get extra objects
            for entity_object in objects_to_get:
                do_export = exporter.get(entity_object['entity_type'],
                                         lambda **kwargs: self.unknown_type({'type': entity_object['entity_type']}))
                entity_object_data = do_export(id=entity_object['id'])
                # Add to result
                entity_object_bundle = self.filter_objects(uuids, entity_object_data)
                uuids = uuids + [x['id'] for x in entity_object_bundle]
                result = result + entity_object_bundle
            for observable_object in observables_to_get:
                observable_object_data = self.export_stix_observable(
                    self.opencti.stix_observable.read(id=observable_object['id'])
                )
                if observable_object_data is not None:
                    observable_object_bundle = self.filter_objects(uuids, observable_object_data)
                    uuids = uuids + [x['id'] for x in observable_object_bundle]
                    result = result + observable_object_bundle
            for relation_object in relations_to_get:
                relation_object_data = self.opencti.stix_relation.to_stix2(id=relation_object['id'])
                relation_object_bundle = self.filter_objects(uuids, relation_object_data)
                uuids = uuids + [x['id'] for x in relation_object_bundle]
                result = result + relation_object_bundle

            # Get extra reports
            for uuid in uuids:
                if 'marking-definition' not in uuid:
                    reports = self.opencti.stix_entity.reports(id=uuid)
                    for report in reports:
                        report_object_data = self.opencti.report.to_stix2(
                            entity=report,
                            mode='simple',
                            max_marking_definition_entity=max_marking_definition_entity
                        )
                        report_object_bundle = self.filter_objects(uuids, report_object_data)
                        uuids = uuids + [x['id'] for x in report_object_bundle]
                        result = result + report_object_bundle

            # Refilter all the reports object refs
            final_result = []
            for entity in result:
                if entity['type'] == 'report':
                    entity['object_refs'] = [k for k in entity['object_refs'] if k in uuids]
                    final_result.append(entity)
                else:
                    final_result.append(entity)
            return final_result
        else:
            return []

    def create_marking_definition(self, stix_object, update=False):
        definition_type = stix_object['definition_type']
        definition = stix_object['definition'][stix_object['definition_type']]
        if stix_object['definition_type'] == 'tlp':
            definition_type = 'TLP'
            definition = 'TLP:' + stix_object['definition'][stix_object['definition_type']].upper()

        return self.opencti.create_marking_definition_if_not_exists(
            definition_type,
            definition,
            stix_object[CustomProperties.LEVEL] if CustomProperties.LEVEL in stix_object else 0,
            stix_object[CustomProperties.COLOR] if CustomProperties.COLOR in stix_object else None,
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'],
            stix_object['created'] if 'created' in stix_object else None,
            stix_object[CustomProperties.MODIFIED] if CustomProperties.MODIFIED in stix_object else None,
        )

    def create_identity(self, stix_object, update=False):
        if CustomProperties.IDENTITY_TYPE in stix_object:
            type = stix_object[CustomProperties.IDENTITY_TYPE].capitalize()
        else:
            if stix_object['identity_class'] == 'individual':
                type = 'User'
            elif stix_object['identity_class'] == 'organization':
                type = 'Organization'
            elif stix_object['identity_class'] == 'group':
                type = 'Organization'
            elif stix_object['identity_class'] == 'class':
                type = 'Sector'
            else:
                return None
        return self.opencti.identity.create(
            type=type,
            name=stix_object['name'],
            description=self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            alias=self.pick_aliases(stix_object),
            id=stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_id_key=stix_object['id'] if 'id' in stix_object else None,
            created=stix_object['created'] if 'created' in stix_object else None,
            modified=stix_object['modified'] if 'modified' in stix_object else None,
            update=update
        )

    def create_threat_actor(self, stix_object, update=False):
        return self.opencti.create_threat_actor_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object['goals'] if 'goals' in stix_object else None,
            stix_object['sophistication'] if 'sophistication' in stix_object else None,
            stix_object['resource_level'] if 'resource_level' in stix_object else None,
            stix_object['primary_motivation'] if 'primary_motivation' in stix_object else None,
            stix_object['secondary_motivations'] if 'secondary_motivations' in stix_object else None,
            stix_object['personal_motivations'] if 'personal_motivations' in stix_object else None,
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    # TODO move in IntrusionSet
    def create_intrusion_set(self, stix_object, update=False):
        return self.opencti.intrusion_set.create(
            name=stix_object['name'],
            description=self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            alias=self.pick_aliases(stix_object),
            first_seen=stix_object[CustomProperties.FIRST_SEEN] if CustomProperties.FIRST_SEEN in stix_object else None,
            last_seen=stix_object[CustomProperties.LAST_SEEN] if CustomProperties.LAST_SEEN in stix_object else None,
            goal=stix_object['goals'] if 'goals' in stix_object else None,
            sophistication=stix_object['sophistication'] if 'sophistication' in stix_object else None,
            resource_level=stix_object['resource_level'] if 'resource_level' in stix_object else None,
            primary_motivation=stix_object['primary_motivation'] if 'primary_motivation' in stix_object else None,
            secondary_motivation=stix_object[
                'secondary_motivations'] if 'secondary_motivations' in stix_object else None,
            id=stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_id_key=stix_object['id'] if 'id' in stix_object else None,
            created=stix_object['created'] if 'created' in stix_object else None,
            modified=stix_object['modified'] if 'modified' in stix_object else None,
            update=update
        )

    # TODO move in Campaign
    def create_campaign(self, stix_object, update=False):
        return self.opencti.create_campaign_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object['objective'] if 'objective' in stix_object else None,
            stix_object[CustomProperties.FIRST_SEEN] if CustomProperties.FIRST_SEEN in stix_object else None,
            stix_object[CustomProperties.LAST_SEEN] if CustomProperties.LAST_SEEN in stix_object else None,
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    # TODO move in Incident
    def create_incident(self, stix_object, update=False):
        return self.opencti.incident.create(
            name=stix_object['name'],
            description=self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            alias=self.pick_aliases(stix_object),
            objective=stix_object['objective'] if 'objective' in stix_object else None,
            first_seen=stix_object['first_seen'] if 'first_seen' in stix_object else None,
            last_seen=stix_object['last_seen'] if 'last_seen' in stix_object else None,
            id=stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_id_key=stix_object['id'] if 'id' in stix_object else None,
            created=stix_object['created'] if 'created' in stix_object else None,
            modified=stix_object['modified'] if 'modified' in stix_object else None,
            update=update
        )

    def create_malware(self, stix_object, update=False):
        return self.opencti.create_malware_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    def create_tool(self, stix_object, update=False):
        return self.opencti.create_tool_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    def create_vulnerability(self, stix_object, update=False):
        return self.opencti.create_vulnerability_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    def create_attack_pattern(self, stix_object, update=False):
        return self.opencti.attack_pattern.import_from_stix2(stixObject=stix_object, update=update)

    def create_course_of_action(self, stix_object, update=False):
        return self.opencti.create_course_of_action_if_not_exists(
            stix_object['name'],
            self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            self.pick_aliases(stix_object),
            stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_object['id'] if 'id' in stix_object else None,
            stix_object['created'] if 'created' in stix_object else None,
            stix_object['modified'] if 'modified' in stix_object else None,
            update
        )

    def create_report(self, stix_object, update=False):
        return self.opencti.report.create(
            name=stix_object['name'],
            description=self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
            published=stix_object['published'] if 'published' in stix_object else '',
            report_class=stix_object[
                CustomProperties.REPORT_CLASS] if CustomProperties.REPORT_CLASS in stix_object else 'Threat Report',
            object_status=stix_object[
                CustomProperties.OBJECT_STATUS] if CustomProperties.OBJECT_STATUS in stix_object else 0,
            source_confidence_level=stix_object[
                CustomProperties.SRC_CONF_LEVEL] if CustomProperties.SRC_CONF_LEVEL in stix_object else 1,
            graph_data=stix_object[CustomProperties.GRAPH_DATA] if CustomProperties.GRAPH_DATA in stix_object else '',
            id=stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
            stix_id_key=stix_object['id'] if 'id' in stix_object else None,
            created=stix_object['created'] if 'created' in stix_object else None,
            modified=stix_object['modified'] if 'modified' in stix_object else None,
            update=update
        )

    def export_stix_observable(self, entity):
        stix_observable = dict()
        stix_observable['id'] = entity['stix_id_key']
        stix_observable['type'] = 'indicator'
        stix_observable['name'] = 'Indicator'
        if self.opencti.not_empty(entity['description']): stix_observable['description'] = entity['description']
        stix_observable['labels'] = ['indicator']
        stix_observable['created'] = self.format_date(entity['created_at'])
        stix_observable['modified'] = self.format_date(entity['updated_at'])
        stix_observable[CustomProperties.OBSERVABLE_TYPE] = entity['entity_type']
        stix_observable[CustomProperties.OBSERVABLE_VALUE] = entity['observable_value']
        stix_observable[CustomProperties.ID] = entity['id']
        if len(entity['stixRelations']) > 0:
            first_seen = utc.localize(datetime.datetime.utcnow())
            for relation in entity['stixRelations']:
                relation_first_seen = dateutil.parser.parse(relation['first_seen'])
                if relation_first_seen < first_seen:
                    first_seen = relation_first_seen
            stix_observable['valid_from'] = self.format_date(first_seen)
        final_stix_observable = self.prepare_observable(entity, stix_observable)
        if final_stix_observable is not None:
            return self.prepare_export(entity, final_stix_observable)
        else:
            return None

    def create_indicator(self, stix_object, update=False):
        indicator_type = None
        indicator_value = None

        # check the custom stix2 fields
        if CustomProperties.OBSERVABLE_TYPE in stix_object and CustomProperties.OBSERVABLE_VALUE in stix_object:
            indicator_type = stix_object[CustomProperties.OBSERVABLE_TYPE]
            indicator_value = stix_object[CustomProperties.OBSERVABLE_VALUE]
        else:
            # check if the indicator is a 'simple' type (i.e it only has exactly one "Comparison Expression")
            # there is no good way of checking this, so this is this is done by using the stix pattern parser, and
            # checking that the pattern's operator is '='
            # The following pattern will be used for reference:
            #   [file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']
            pattern = stix2.pattern_visitor.create_pattern_object(stix_object['pattern'])
            if pattern.operand.operator == '=':

                # get the object type (here 'file') and check that it is a standard observable type
                object_type = pattern.operand.lhs.object_type_name
                if object_type in stix2.OBJ_MAP_OBSERVABLE:

                    # get the left hand side as string and use it for looking up the correct OpenCTI name
                    lhs = str(pattern.operand.lhs)  # this is "file:hashes.md5" from the reference pattern
                    if lhs in STIX2OPENCTI:
                        # the type and value can now be set
                        indicator_type = STIX2OPENCTI[lhs]
                        indicator_value = pattern.operand.rhs.value

        # check that the indicator type and value have been set before creating the indicator
        if indicator_type and indicator_value:
            return self.opencti.stix_observable.create(
                type=indicator_type,
                observable_value=indicator_value,
                description=self.convert_markdown(stix_object['description']) if 'description' in stix_object else '',
                id=stix_object[CustomProperties.ID] if CustomProperties.ID in stix_object else None,
                stix_id_key=stix_object['id'] if 'id' in stix_object else None,
                update=update
            )
        else:
            # log that the indicator could not be parsed
            self.opencti.log('info', "Cannot handle indicator: {id}".format(id=stix_object['stix_id_key']))

        return None

    def resolve_author(self, title):
        if 'fireeye' in title.lower() or 'mandiant' in title.lower():
            return self.get_author('FireEye')
        if 'eset' in title.lower():
            return self.get_author('ESET')
        if 'dragos' in title.lower():
            return self.get_author('Dragos')
        if 'us-cert' in title.lower():
            return self.get_author('US-CERT')
        if 'unit 42' in title.lower() or 'unit42' in title.lower() or 'palo alto' in title.lower():
            return self.get_author('Palo Alto Networks')
        if 'accenture' in title.lower():
            return self.get_author('Accenture')
        if 'symantec' in title.lower():
            return self.get_author('Symantec')
        if 'trendmicro' in title.lower() or 'trend micro' in title.lower():
            return self.get_author('Trend Micro')
        if 'mcafee' in title.lower():
            return self.get_author('McAfee')
        if 'crowdstrike' in title.lower():
            return self.get_author('CrowdStrike')
        if 'securelist' in title.lower() or 'kaspersky' in title.lower():
            return self.get_author('Kaspersky')
        if 'f-secure' in title.lower():
            return self.get_author('F-Secure')
        if 'checkpoint' in title.lower():
            return self.get_author('CheckPoint')
        if 'talos' in title.lower():
            return self.get_author('Cisco Talos')
        if 'secureworks' in title.lower():
            return self.get_author('Dell SecureWorks')
        if 'microsoft' in title.lower():
            return self.get_author('Microsoft')
        if 'mitre att&ck' in title.lower():
            return self.get_author('The MITRE Corporation')
        return None

    def prepare_observable(self, entity, stix_observable):
        if 'file' in entity['entity_type']:
            observable_type = 'file'
        elif entity['entity_type'] == 'domain':
            observable_type = 'domain-name'
        else:
            observable_type = entity['entity_type']

        try:
            if observable_type == 'file':
                lhs = ObjectPath(observable_type, ['hashes', entity['entity_type'].split('-')[1].upper()])
                ece = ObservationExpression(
                    EqualityComparisonExpression(
                        lhs,
                        HashConstant(
                            entity['observable_value'],
                            entity['entity_type'].split('-')[1].upper())
                    )
                )
            else:
                lhs = ObjectPath(observable_type, ["value"])
                ece = ObservationExpression(
                    EqualityComparisonExpression(
                        lhs,
                        entity['observable_value'])
                )
        except:
            ece = None
        if ece is not None:
            stix_observable['pattern'] = str(ece)
            return stix_observable
        else:
            return None

    def get_author(self, name):
        if name in self.mapping_cache:
            return self.mapping_cache[name]
        else:
            author = self.opencti.identity.create(
                type='Organization',
                name=name,
                description='',
            )
            self.mapping_cache[name] = author
            return author

    def import_bundle(self, stix_bundle, update=False, types=None) -> List:
        if types is None:
            types = []
        self.mapping_cache = {}
        # Check if the bundle is correctly formatted
        if 'type' not in stix_bundle or stix_bundle['type'] != 'bundle':
            raise ValueError('JSON data type is not a STIX2 bundle')
        if 'objects' not in stix_bundle or len(stix_bundle['objects']) == 0:
            raise ValueError('JSON data objects is empty')

        # Import every elements in a specific order
        imported_elements = []

        # Marking definitions
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'marking-definition':
                self.import_object(item, update, types)
                imported_elements.append({'id': item['id'], 'type': item['type']})
        end_time = time.time()
        self.opencti.log('info', "Marking definitions imported in: %ssecs" % round(end_time - start_time))

        # Identities
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'identity' and (len(types) == 0 or 'identity' in types or (
                    CustomProperties.IDENTITY_TYPE in item and item[CustomProperties.IDENTITY_TYPE] in types)):
                self.import_object(item, update, types)
                imported_elements.append({'id': item['id'], 'type': item['type']})
        end_time = time.time()
        self.opencti.log('info', "Identities imported in: %ssecs" % round(end_time - start_time))

        # StixDomainObjects except Report
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] != 'relationship' and item['type'] != 'report' and item['type'] != 'observed-data' and (
                    len(types) == 0 or item['type'] in types):
                self.import_object(item, update, types)
                imported_elements.append({'id': item['id'], 'type': item['type']})
        end_time = time.time()
        self.opencti.log('info', "Objects imported in: %ssecs" % round(end_time - start_time))

        # StixRelationObjects
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'relationship':
                self.import_relationship(item, update, types)
                imported_elements.append({'id': item['id'], 'type': item['type']})
        end_time = time.time()
        self.opencti.log('info', "Relationships imported in: %ssecs" % round(end_time - start_time))

        # StixCyberObservables
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'observed-data' and (len(types) == 0 or 'observed-data' in types):
                self.import_observables(item)
        end_time = time.time()
        self.opencti.log('info', "Observables imported in: %ssecs" % round(end_time - start_time))

        # Reports
        start_time = time.time()
        for item in stix_bundle['objects']:
            if item['type'] == 'report' and (len(types) == 0 or 'report' in types):
                self.import_object(item, update, types)
                imported_elements.append({'id': item['id'], 'type': item['type']})
        end_time = time.time()
        self.opencti.log('info', "Reports imported in: %ssecs" % round(end_time - start_time))
        return imported_elements
