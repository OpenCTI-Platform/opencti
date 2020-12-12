# coding: utf-8

from pycti.utils.constants import (
    StixCyberObservableTypes,
)


class OpenCTIStix2Update:
    """Python API for Stix2 Update in OpenCTI

    :param opencti: OpenCTI instance
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.mapping_cache = {}

    def add_object_marking_refs(self, entity_type, id, object_marking_refs):
        for object_marking_ref in object_marking_refs:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_marking_definition(
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

    def remove_object_marking_refs(self, entity_type, id, object_marking_refs):
        for object_marking_ref in object_marking_refs:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_marking_definition(
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

    def add_external_references(self, entity_type, id, external_references):
        for external_reference in external_references:
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

    def add_kill_chain_phases(self, entity_type, id, kill_chain_phases):
        for kill_chain_phase in kill_chain_phases:
            kill_chain_phase_id = self.opencti.kill_chain_phase.create(
                kill_chain_name=kill_chain_phase["kill_chain_name"],
                phase_name=kill_chain_phase["phase_name"],
                phase_order=kill_chain_phase["x_opencti_order"]
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

    def add_object_refs(self, entity_type, id, object_refs):
        for object_ref in object_refs:
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

    def remove_object_refs(self, entity_type, id, object_refs):
        for object_ref in object_refs:
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

    def add_labels(self, entity_type, id, labels):
        for label in labels:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.add_label(id=id, label_name=label)
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.add_label(id=id, label_name=label)
            else:
                self.opencti.stix_domain_object.add_label(id=id, label_name=label)

    def remove_labels(self, entity_type, id, labels):
        for label in labels:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_label(
                    id=id, label_name=label
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_label(id=id, label_name=label)
            else:
                self.opencti.stix_domain_object.remove_label(id=id, label_name=label)

    def update_attribute(self, entity_type, id, operation, key, value):
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_field(
                id=id, key=key, value=value, operation=operation
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            self.opencti.stix_cyber_observable.update_field(
                id=id, key=key, value=value, operation=operation
            )
        else:
            self.opencti.stix_domain_object.update_field(
                id=id, key=key, value=value, operation=operation
            )

    def replace_created_by_ref(self, entity_type, id, created_by_ref):
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_created_by(
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

    def process_update(self, data):
        try:
            if "add" in data["x_data_update"]:
                for key in data["x_data_update"]["add"].keys():
                    if key == "object_marking_refs":
                        self.add_object_marking_refs(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["object_marking_refs"],
                        )
                    elif key == "object_refs":
                        self.add_object_refs(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["object_refs"],
                        )
                    elif key == "labels":
                        self.add_labels(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["labels"],
                        )
                    elif key == "external_references":
                        self.add_external_references(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["external_references"],
                        )
                    elif key == "kill_chain_phases":
                        self.add_kill_chain_phases(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["kill_chain_phases"],
                        )
                    elif key == "created_by_ref":
                        self.replace_created_by_ref(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["add"]["created_by_ref"],
                        )
                    else:
                        self.update_attribute(
                            data["type"],
                            data["id"],
                            "add",
                            key,
                            data["x_data_update"]["add"][key],
                        )
            if "remove" in data["x_data_update"]:
                for key in data["x_data_update"]["remove"].keys():
                    if key == "object_marking_refs":
                        self.remove_object_marking_refs(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["remove"]["object_marking_refs"],
                        )
                    elif key == "object_refs":
                        self.remove_object_refs(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["remove"]["object_refs"],
                        )
                    elif key == "labels":
                        self.remove_labels(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["remove"]["labels"],
                        )
                    elif key == "external_references":
                        self.remove_external_references(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["remove"]["external_references"],
                        )
                    elif key == "kill_chain_phases":
                        self.remove_kill_chain_phases(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["remove"]["kill_chain_phases"],
                        )
                    elif key == "created_by_ref":
                        self.replace_created_by_ref(
                            data["type"],
                            data["id"],
                            None,
                        )
                    else:
                        self.update_attribute(
                            data["type"],
                            data["id"],
                            "remove",
                            key,
                            data["x_data_update"]["remove"][key],
                        )
            if "replace" in data["x_data_update"]:
                for key in data["x_data_update"]["replace"].keys():
                    if key == "created_by_ref":
                        self.replace_created_by_ref(
                            data["type"],
                            data["id"],
                            data["x_data_update"]["replace"]["created_by_ref"],
                        )
                    else:
                        self.update_attribute(
                            data["type"],
                            data["id"],
                            "replace",
                            key,
                            data["x_data_update"]["replace"][key],
                        )
        except:
            self.opencti.log("error", "Cannot process this message")
            pass
