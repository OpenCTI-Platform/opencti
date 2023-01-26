# coding: utf-8

from pycti.api import LOGGER as API_LOGGER
from pycti.utils.constants import StixCyberObservableTypes


class OpenCTIStix2Update:
    """Python API for Stix2 Update in OpenCTI

    :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.mapping_cache = {}

    def add_object_marking_refs(self, entity_type, id, object_marking_refs, version=2):
        for object_marking_ref in object_marking_refs:
            if version == 2:
                object_marking_ref = object_marking_ref["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif entity_type == "sighting":
                self.opencti.stix_sighting_relationship.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            else:
                self.opencti.stix_domain_object.add_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )

    def remove_object_marking_refs(
        self, entity_type, id, object_marking_refs, version=2
    ):
        for object_marking_ref in object_marking_refs:
            if version == 2:
                object_marking_ref = object_marking_ref["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif entity_type == "sighting":
                self.opencti.stix_sighting_relationship.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )
            else:
                self.opencti.stix_domain_object.remove_marking_definition(
                    id=id, marking_definition_id=object_marking_ref
                )

    def add_external_references(self, entity_type, id, external_references, version=2):
        for external_reference in external_references:
            if version == 2:
                external_reference = external_reference["value"]
            if "url" in external_reference and "source_name" in external_reference:
                url = external_reference["url"]
                source_name = external_reference["source_name"]
            else:
                continue
            external_reference_id = self.opencti.external_reference.create(
                source_name=source_name,
                url=url,
                external_id=external_reference["external_id"]
                if "external_id" in external_reference
                else None,
                description=external_reference["description"]
                if "description" in external_reference
                else None,
            )["id"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_external_reference(
                    id=id, external_reference_id=external_reference_id
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.add_external_reference(
                    id=id, external_reference_id=external_reference_id
                )
            else:
                self.opencti.stix_domain_object.add_external_reference(
                    id=id, external_reference_id=external_reference_id
                )

    def remove_external_references(self, entity_type, id, external_references):
        for external_reference in external_references:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_external_reference(
                    id=id, external_reference_id=external_reference["id"]
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_external_reference(
                    id=id, external_reference_id=external_reference["id"]
                )
            else:
                self.opencti.stix_domain_object.remove_external_reference(
                    id=id, external_reference_id=external_reference["id"]
                )

    def add_kill_chain_phases(self, entity_type, id, kill_chain_phases, version=2):
        for kill_chain_phase in kill_chain_phases:
            if version == 2:
                kill_chain_phase = kill_chain_phase["value"]
            kill_chain_phase_id = self.opencti.kill_chain_phase.create(
                kill_chain_name=kill_chain_phase["kill_chain_name"],
                phase_name=kill_chain_phase["phase_name"],
                x_opencti_order=kill_chain_phase["x_opencti_order"]
                if "x_opencti_order" in kill_chain_phase
                else 0,
                stix_id=kill_chain_phase["id"] if "id" in kill_chain_phase else None,
            )["id"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase_id
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.add_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase_id
                )
            else:
                self.opencti.stix_domain_object.add_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase_id
                )

    def remove_kill_chain_phases(self, entity_type, id, kill_chain_phases):
        for kill_chain_phase in kill_chain_phases:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase["id"]
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase["id"]
                )
            else:
                self.opencti.stix_domain_object.remove_kill_chain_phase(
                    id=id, kill_chain_phase_id=kill_chain_phase["id"]
                )

    def add_object_refs(self, entity_type, id, object_refs, version=2):
        for object_ref in object_refs:
            if version == 2:
                object_ref = object_ref["value"]
            if entity_type == "report":
                self.opencti.report.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "note":
                self.opencti.note.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "observed-data":
                self.opencti.observed_data.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "opinion":
                self.opencti.opinion.add_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )

    def remove_object_refs(self, entity_type, id, object_refs, version=2):
        for object_ref in object_refs:
            if version == 2:
                object_ref = object_ref["value"]
            if entity_type == "report":
                self.opencti.report.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "note":
                self.opencti.note.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "observed-data":
                self.opencti.observed_data.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "opinion":
                self.opencti.opinion.remove_stix_object_or_stix_relationship(
                    id=id, stixObjectOrStixRelationshipId=object_ref
                )

    def add_labels(self, entity_type, id, labels, version=2):
        for label in labels:
            if version == 2:
                label = label["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_label(id=id, label_name=label)
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.add_label(id=id, label_name=label)
            else:
                self.opencti.stix_domain_object.add_label(id=id, label_name=label)

    def remove_labels(self, entity_type, id, labels, version=2):
        for label in labels:
            if version == 2:
                label = label["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_label(
                    id=id, label_name=label
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_label(id=id, label_name=label)
            else:
                self.opencti.stix_domain_object.remove_label(id=id, label_name=label)

    def replace_created_by_ref(self, entity_type, id, created_by_ref, version=2):
        if version == 2:
            created_by_ref = (
                created_by_ref[0]["value"] if created_by_ref is not None else None
            )
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_created_by(
                id=id, identity_id=created_by_ref
            )
        elif entity_type == "sighting":
            self.opencti.stix_sighting_relationship.update_created_by(
                id=id, identity_id=created_by_ref
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            self.opencti.stix_cyber_observable.update_created_by(
                id=id, identity_id=created_by_ref
            )
        else:
            self.opencti.stix_domain_object.update_created_by(
                id=id, identity_id=created_by_ref
            )

    def update_attribute(self, entity_type, id, input):
        # Relations
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_field(id=id, input=input)
        elif entity_type == "sighting":
            self.opencti.stix_sighting_relationship.update_field(id=id, input=input)
        # Observables
        elif StixCyberObservableTypes.has_value(entity_type):
            self.opencti.stix_cyber_observable.update_field(id=id, input=input)
        # Meta
        elif entity_type == "marking-definition":
            self.opencti.marking_definition.update_field(id=id, input=input)
        elif entity_type == "label":
            self.opencti.label.update_field(id=id, input=input)
        elif entity_type == "vocabulary":
            self.opencti.vocabulary.update_field(id=id, input=input)
        elif entity_type == "kill-chain-phase":
            self.opencti.kill_chain_phase.update_field(id=id, input=input)
        elif entity_type == "external-reference":
            self.opencti.external_reference.update_field(id=id, input=input)
        # Remaining stix domain
        else:
            self.opencti.stix_domain_object.update_field(id=id, input=input)

    def process_update(self, data):
        try:
            # Build the inputs fo update api
            inputs = []
            if "add" in data["x_opencti_patch"]:
                for key in data["x_opencti_patch"]["add"].keys():
                    val = data["x_opencti_patch"]["add"][key]
                    values = list(map(lambda x: x["value"] if "value" in x else x, val))
                    inputs.append({"key": key, "value": values, "operation": "add"})
            if "remove" in data["x_opencti_patch"]:
                for key in data["x_opencti_patch"]["remove"].keys():
                    val = data["x_opencti_patch"]["remove"][key]
                    values = list(map(lambda x: x["value"] if "value" in x else x, val))
                    inputs.append({"key": key, "value": values, "operation": "remove"})
            if "replace" in data["x_opencti_patch"]:
                for key in data["x_opencti_patch"]["replace"].keys():
                    if (
                        key != "id"
                    ):  # ID replace is a side effect handled by the platform
                        val = data["x_opencti_patch"]["replace"][key]
                        current_val = val["current"]
                        if type(current_val) is list:
                            values = list(
                                map(
                                    lambda x: x["value"]
                                    if (type(current_val) is dict and "value" in x)
                                    else x,
                                    str(current_val),
                                )
                            )
                            inputs.append({"key": key, "value": values})
                        else:
                            values = (
                                current_val["value"]
                                if (
                                    type(current_val) is dict and "value" in current_val
                                )
                                else str(current_val)
                            )
                            inputs.append({"key": key, "value": values})
            self.update_attribute(data["type"], data["id"], inputs)
        except Exception as e:
            print(e)
            print(data)
            API_LOGGER.error("Cannot process this message")
