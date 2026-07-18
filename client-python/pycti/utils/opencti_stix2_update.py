from pycti.utils.constants import StixCyberObservableTypes

OBJECT_REF_CREATE_BATCH_SIZE = 100
OBJECT_MARKING_REF_CREATE_BATCH_SIZE = 100
EXTERNAL_REFERENCE_RELATION_CREATE_BATCH_SIZE = 100
KILL_CHAIN_PHASE_RELATION_CREATE_BATCH_SIZE = 100
EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE = 1000
KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE = 1000
LABEL_PREFETCH_BATCH_SIZE = 1000
LABEL_RELATION_CREATE_BATCH_SIZE = 100
BULK_REF_RELATION_VALIDATION_API_FEATURE = "BULK_REF_RELATION_VALIDATION"
_OBJECT_REF_ENTITY_ATTRIBUTES = {
    "report": "report",
    "note": "note",
    "observed-data": "observed_data",
    "opinion": "opinion",
    "grouping": "grouping",
    "case-incident": "case_incident",
    "case-rfi": "case_rfi",
    "case-rft": "case_rft",
    "feedback": "feedback",
    "task": "task",
}


class OpenCTIStix2Update:
    """Python API for Stix2 Update in OpenCTI.

    Provides methods to update STIX2 objects in OpenCTI, including
    adding/removing marking definitions, labels, external references,
    kill chain phases, and object references.

    :param opencti: OpenCTI API client instance
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the OpenCTIStix2Update helper.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti

    def add_object_marking_refs(
        self, entity_type, entity_id, object_marking_refs, version=2
    ):
        """Add marking definition references to an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param object_marking_refs: List of marking definition references
        :type object_marking_refs: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        normalized_object_marking_refs = [
            object_marking_ref["value"] if version == 2 else object_marking_ref
            for object_marking_ref in object_marking_refs
        ]
        if len(normalized_object_marking_refs) == 0:
            return

        nested_ref_relationship = getattr(
            self.opencti, "stix_nested_ref_relationship", None
        )
        if entity_type == "relationship":
            add_marking_definition = (
                self.opencti.stix_core_relationship.add_marking_definition
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_relationship", None
            )
        elif entity_type == "sighting":
            add_marking_definition = (
                self.opencti.stix_sighting_relationship.add_marking_definition
            )
            add_many = getattr(
                nested_ref_relationship,
                "add_many_to_stix_sighting_relationship",
                None,
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            add_marking_definition = (
                self.opencti.stix_cyber_observable.add_marking_definition
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )
        else:
            add_marking_definition = (
                self.opencti.stix_domain_object.add_marking_definition
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )

        can_bulk_marking_refs = (
            add_many is not None and len(normalized_object_marking_refs) > 1
        )
        if can_bulk_marking_refs:
            supports_api_feature = getattr(self.opencti, "supports_api_feature", None)
            can_bulk_marking_refs = (
                supports_api_feature is not None
                and supports_api_feature(BULK_REF_RELATION_VALIDATION_API_FEATURE)
            )
        if not can_bulk_marking_refs:
            for object_marking_ref in normalized_object_marking_refs:
                add_marking_definition(
                    id=entity_id, marking_definition_id=object_marking_ref
                )
            return

        for start_index in range(
            0,
            len(normalized_object_marking_refs),
            OBJECT_MARKING_REF_CREATE_BATCH_SIZE,
        ):
            batch_object_marking_refs = normalized_object_marking_refs[
                start_index : start_index + OBJECT_MARKING_REF_CREATE_BATCH_SIZE
            ]
            if len(batch_object_marking_refs) == 1:
                add_marking_definition(
                    id=entity_id,
                    marking_definition_id=batch_object_marking_refs[0],
                )
            else:
                add_many(entity_id, batch_object_marking_refs, "object-marking")

    def remove_object_marking_refs(
        self, entity_type, entity_id, object_marking_refs, version=2
    ):
        """Remove marking definition references from an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param object_marking_refs: List of marking definition references
        :type object_marking_refs: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        for object_marking_ref in object_marking_refs:
            if version == 2:
                object_marking_ref = object_marking_ref["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_marking_definition(
                    id=entity_id, marking_definition_id=object_marking_ref
                )
            elif entity_type == "sighting":
                self.opencti.stix_sighting_relationship.remove_marking_definition(
                    id=entity_id, marking_definition_id=object_marking_ref
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_marking_definition(
                    id=entity_id, marking_definition_id=object_marking_ref
                )
            else:
                self.opencti.stix_domain_object.remove_marking_definition(
                    id=entity_id, marking_definition_id=object_marking_ref
                )

    def add_external_references(
        self, entity_type, entity_id, external_references, version=2
    ):
        """Add external references to an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param external_references: List of external references
        :type external_references: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        nested_ref_relationship = getattr(
            self.opencti, "stix_nested_ref_relationship", None
        )
        if entity_type == "relationship":
            add_external_reference = (
                self.opencti.stix_core_relationship.add_external_reference
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_relationship", None
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            add_external_reference = (
                self.opencti.stix_cyber_observable.add_external_reference
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )
        else:
            add_external_reference = (
                self.opencti.stix_domain_object.add_external_reference
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )

        normalized_external_references = []
        for external_reference in external_references:
            if version == 2:
                external_reference = external_reference["value"]
            if "url" in external_reference and "source_name" in external_reference:
                normalized_external_references.append(external_reference)
        if len(normalized_external_references) == 0:
            return

        prefetched_external_reference_ids = self._prefetch_patch_external_references(
            normalized_external_references
        )
        pending_external_reference_ids = []
        for external_reference in normalized_external_references:
            external_reference_id = None
            cache_key = None
            if prefetched_external_reference_ids is not None:
                cache_key = self._patch_external_reference_cache_key(external_reference)
                external_reference_id = prefetched_external_reference_ids.get(cache_key)
            if external_reference_id is None:
                external_reference_data = self.opencti.external_reference.create(
                    source_name=external_reference["source_name"],
                    url=external_reference["url"],
                    external_id=external_reference.get("external_id"),
                    description=external_reference.get("description"),
                )
                external_reference_id = external_reference_data["id"]
                if (
                    prefetched_external_reference_ids is not None
                    and cache_key is not None
                ):
                    prefetched_external_reference_ids[cache_key] = external_reference_id
            pending_external_reference_ids.append(external_reference_id)
            if (
                len(pending_external_reference_ids)
                >= EXTERNAL_REFERENCE_RELATION_CREATE_BATCH_SIZE
            ):
                self._flush_external_reference_relation_batch(
                    entity_id,
                    pending_external_reference_ids,
                    add_external_reference,
                    add_many,
                )
                pending_external_reference_ids = []
        self._flush_external_reference_relation_batch(
            entity_id,
            pending_external_reference_ids,
            add_external_reference,
            add_many,
        )

    @staticmethod
    def _patch_external_reference_cache_key(external_reference):
        return (
            external_reference.get("source_name"),
            external_reference.get("url"),
            external_reference.get("external_id"),
            external_reference.get("description"),
        )

    def _prefetch_patch_external_references(self, external_references):
        if len(external_references) <= 1:
            return None

        cache_keys_by_generated_ref_id = {}
        try:
            for external_reference in external_references:
                generated_ref_id = self.opencti.external_reference.generate_id(
                    external_reference.get("url"),
                    external_reference.get("source_name"),
                    external_reference.get("external_id"),
                )
                if generated_ref_id is None:
                    continue
                cache_key = self._patch_external_reference_cache_key(external_reference)
                cache_keys_by_generated_ref_id.setdefault(generated_ref_id, set()).add(
                    cache_key
                )

            if len(cache_keys_by_generated_ref_id) == 0:
                return None

            prefetched_external_reference_ids = {}
            generated_ref_ids = list(cache_keys_by_generated_ref_id.keys())
            for start_index in range(
                0, len(generated_ref_ids), EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE
            ):
                batch_generated_ref_ids = generated_ref_ids[
                    start_index : start_index + EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE
                ]
                external_reference_data_list = (
                    self.opencti.external_reference.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "ids",
                                    "values": batch_generated_ref_ids,
                                }
                            ],
                            "filterGroups": [],
                        },
                        getAll=True,
                    )
                    or []
                )
                for external_reference_data in external_reference_data_list:
                    generated_ref_id = external_reference_data.get("standard_id")
                    if generated_ref_id is None:
                        generated_ref_id = self.opencti.external_reference.generate_id(
                            external_reference_data.get("url"),
                            external_reference_data.get("source_name"),
                            external_reference_data.get("external_id"),
                        )
                    candidate_cache_keys = cache_keys_by_generated_ref_id.get(
                        generated_ref_id
                    )
                    if candidate_cache_keys is None:
                        continue
                    cache_key = self._patch_external_reference_cache_key(
                        external_reference_data
                    )
                    if cache_key in candidate_cache_keys:
                        prefetched_external_reference_ids[cache_key] = (
                            external_reference_data["id"]
                        )
            return prefetched_external_reference_ids
        except Exception:
            return None

    @staticmethod
    def _flush_external_reference_relation_batch(
        entity_id, external_reference_ids, add_external_reference, add_many
    ):
        if len(external_reference_ids) == 0:
            return
        if add_many is None or len(external_reference_ids) == 1:
            for external_reference_id in external_reference_ids:
                add_external_reference(
                    id=entity_id, external_reference_id=external_reference_id
                )
            return
        add_many(entity_id, external_reference_ids, "external-reference")

    def remove_external_references(self, entity_type, entity_id, external_references):
        """Remove external references from an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param external_references: List of external references
        :type external_references: list
        """
        for external_reference in external_references:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_external_reference(
                    id=entity_id, external_reference_id=external_reference["id"]
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_external_reference(
                    id=entity_id, external_reference_id=external_reference["id"]
                )
            else:
                self.opencti.stix_domain_object.remove_external_reference(
                    id=entity_id, external_reference_id=external_reference["id"]
                )

    def add_kill_chain_phases(
        self, entity_type, entity_id, kill_chain_phases, version=2
    ):
        """Add kill chain phases to an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param kill_chain_phases: List of kill chain phases
        :type kill_chain_phases: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        nested_ref_relationship = getattr(
            self.opencti, "stix_nested_ref_relationship", None
        )
        if entity_type == "relationship":
            add_kill_chain_phase = (
                self.opencti.stix_core_relationship.add_kill_chain_phase
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_relationship", None
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            add_kill_chain_phase = (
                self.opencti.stix_cyber_observable.add_kill_chain_phase
            )
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )
        else:
            add_kill_chain_phase = self.opencti.stix_domain_object.add_kill_chain_phase
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )

        normalized_kill_chain_phases = []
        for kill_chain_phase in kill_chain_phases:
            if version == 2:
                kill_chain_phase = kill_chain_phase["value"]
            normalized_kill_chain_phases.append(kill_chain_phase)
        if len(normalized_kill_chain_phases) == 0:
            return

        prefetched_kill_chain_phase_ids = self._prefetch_patch_kill_chain_phases(
            normalized_kill_chain_phases
        )
        pending_kill_chain_phase_ids = []
        for kill_chain_phase in normalized_kill_chain_phases:
            kill_chain_phase_id = None
            cache_key = None
            if (
                prefetched_kill_chain_phase_ids is not None
                and "id" not in kill_chain_phase
            ):
                cache_key = self._patch_kill_chain_phase_cache_key(kill_chain_phase)
                kill_chain_phase_id = prefetched_kill_chain_phase_ids.get(cache_key)
            if kill_chain_phase_id is None:
                kill_chain_phase_data = self.opencti.kill_chain_phase.create(
                    kill_chain_name=kill_chain_phase["kill_chain_name"],
                    phase_name=kill_chain_phase["phase_name"],
                    x_opencti_order=kill_chain_phase.get("x_opencti_order", 0),
                    stix_id=kill_chain_phase.get("id"),
                )
                kill_chain_phase_id = kill_chain_phase_data["id"]
                if (
                    prefetched_kill_chain_phase_ids is not None
                    and cache_key is not None
                ):
                    prefetched_kill_chain_phase_ids[cache_key] = kill_chain_phase_id
            pending_kill_chain_phase_ids.append(kill_chain_phase_id)
            if (
                len(pending_kill_chain_phase_ids)
                >= KILL_CHAIN_PHASE_RELATION_CREATE_BATCH_SIZE
            ):
                self._flush_kill_chain_phase_relation_batch(
                    entity_id,
                    pending_kill_chain_phase_ids,
                    add_kill_chain_phase,
                    add_many,
                )
                pending_kill_chain_phase_ids = []
        self._flush_kill_chain_phase_relation_batch(
            entity_id,
            pending_kill_chain_phase_ids,
            add_kill_chain_phase,
            add_many,
        )

    @staticmethod
    def _patch_kill_chain_phase_cache_key(kill_chain_phase):
        return (
            kill_chain_phase.get("kill_chain_name"),
            kill_chain_phase.get("phase_name"),
            kill_chain_phase.get("x_opencti_order", 0),
        )

    def _prefetch_patch_kill_chain_phases(self, kill_chain_phases):
        if len(kill_chain_phases) <= 1:
            return None

        cache_keys_by_generated_phase_id = {}
        try:
            for kill_chain_phase in kill_chain_phases:
                if "id" in kill_chain_phase:
                    continue
                generated_phase_id = self.opencti.kill_chain_phase.generate_id(
                    kill_chain_phase["phase_name"],
                    kill_chain_phase["kill_chain_name"],
                )
                cache_key = self._patch_kill_chain_phase_cache_key(kill_chain_phase)
                cache_keys_by_generated_phase_id.setdefault(
                    generated_phase_id, set()
                ).add(cache_key)

            if len(cache_keys_by_generated_phase_id) == 0:
                return None

            prefetched_kill_chain_phase_ids = {}
            generated_phase_ids = list(cache_keys_by_generated_phase_id.keys())
            for start_index in range(
                0, len(generated_phase_ids), KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE
            ):
                batch_generated_phase_ids = generated_phase_ids[
                    start_index : start_index + KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE
                ]
                kill_chain_phase_data_list = (
                    self.opencti.kill_chain_phase.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "ids",
                                    "values": batch_generated_phase_ids,
                                }
                            ],
                            "filterGroups": [],
                        },
                        first=len(batch_generated_phase_ids),
                    )
                    or []
                )
                for kill_chain_phase_data in kill_chain_phase_data_list:
                    generated_phase_id = kill_chain_phase_data.get("standard_id")
                    if generated_phase_id is None:
                        generated_phase_id = self.opencti.kill_chain_phase.generate_id(
                            kill_chain_phase_data["phase_name"],
                            kill_chain_phase_data["kill_chain_name"],
                        )
                    candidate_cache_keys = cache_keys_by_generated_phase_id.get(
                        generated_phase_id
                    )
                    if candidate_cache_keys is None:
                        continue
                    cache_key = self._patch_kill_chain_phase_cache_key(
                        kill_chain_phase_data
                    )
                    if cache_key in candidate_cache_keys:
                        prefetched_kill_chain_phase_ids[cache_key] = (
                            kill_chain_phase_data["id"]
                        )
            return prefetched_kill_chain_phase_ids
        except Exception:
            return None

    @staticmethod
    def _flush_kill_chain_phase_relation_batch(
        entity_id, kill_chain_phase_ids, add_kill_chain_phase, add_many
    ):
        if len(kill_chain_phase_ids) == 0:
            return
        if add_many is None or len(kill_chain_phase_ids) == 1:
            for kill_chain_phase_id in kill_chain_phase_ids:
                add_kill_chain_phase(
                    id=entity_id, kill_chain_phase_id=kill_chain_phase_id
                )
            return
        add_many(entity_id, kill_chain_phase_ids, "kill-chain-phase")

    def remove_kill_chain_phases(self, entity_type, entity_id, kill_chain_phases):
        """Remove kill chain phases from an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param kill_chain_phases: List of kill chain phases
        :type kill_chain_phases: list
        """
        for kill_chain_phase in kill_chain_phases:
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_kill_chain_phase(
                    id=entity_id, kill_chain_phase_id=kill_chain_phase["id"]
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_kill_chain_phase(
                    id=entity_id, kill_chain_phase_id=kill_chain_phase["id"]
                )
            else:
                self.opencti.stix_domain_object.remove_kill_chain_phase(
                    id=entity_id, kill_chain_phase_id=kill_chain_phase["id"]
                )

    def add_object_refs(self, entity_type, entity_id, object_refs, version=2):
        """Add object references to a container entity.

        :param entity_type: Type of the container entity (report, note, etc.)
        :type entity_type: str
        :param entity_id: ID of the container entity
        :type entity_id: str
        :param object_refs: List of object references to add
        :type object_refs: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        entity_attribute = _OBJECT_REF_ENTITY_ATTRIBUTES.get(entity_type)
        if entity_attribute is None:
            return

        object_ref_adder = getattr(
            getattr(self.opencti, entity_attribute),
            "add_stix_object_or_stix_relationship",
        )
        normalized_object_refs = [
            object_ref["value"] if version == 2 else object_ref
            for object_ref in object_refs
        ]
        if len(normalized_object_refs) == 0:
            return

        nested_ref_relationship = getattr(
            self.opencti, "stix_nested_ref_relationship", None
        )
        add_many = getattr(
            nested_ref_relationship, "add_many_to_stix_core_object", None
        )
        if add_many is None or len(normalized_object_refs) == 1:
            for object_ref in normalized_object_refs:
                object_ref_adder(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            return

        for start_index in range(
            0, len(normalized_object_refs), OBJECT_REF_CREATE_BATCH_SIZE
        ):
            batch_object_refs = normalized_object_refs[
                start_index : start_index + OBJECT_REF_CREATE_BATCH_SIZE
            ]
            if len(batch_object_refs) == 1:
                object_ref_adder(
                    id=entity_id,
                    stixObjectOrStixRelationshipId=batch_object_refs[0],
                )
            else:
                add_many(entity_id, batch_object_refs, "object")

    def remove_object_refs(self, entity_type, entity_id, object_refs, version=2):
        """Remove object references from a container entity.

        :param entity_type: Type of the container entity (report, note, etc.)
        :type entity_type: str
        :param entity_id: ID of the container entity
        :type entity_id: str
        :param object_refs: List of object references to remove
        :type object_refs: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        for object_ref in object_refs:
            if version == 2:
                object_ref = object_ref["value"]
            if entity_type == "report":
                self.opencti.report.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "note":
                self.opencti.note.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "observed-data":
                self.opencti.observed_data.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "opinion":
                self.opencti.opinion.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "grouping":
                self.opencti.grouping.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "case-incident":
                self.opencti.case_incident.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "case-rfi":
                self.opencti.case_rfi.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "case-rft":
                self.opencti.case_rft.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "feedback":
                self.opencti.feedback.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )
            elif entity_type == "task":
                self.opencti.task.remove_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=object_ref
                )

    def add_labels(self, entity_type, entity_id, labels, version=2):
        """Add labels to an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param labels: List of labels to add
        :type labels: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        normalized_labels = [
            label["value"] if version == 2 else label for label in labels
        ]
        if len(normalized_labels) == 0:
            return

        nested_ref_relationship = getattr(
            self.opencti, "stix_nested_ref_relationship", None
        )
        if entity_type == "relationship":
            add_label = self.opencti.stix_core_relationship.add_label
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_relationship", None
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            add_label = self.opencti.stix_cyber_observable.add_label
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )
        else:
            add_label = self.opencti.stix_domain_object.add_label
            add_many = getattr(
                nested_ref_relationship, "add_many_to_stix_core_object", None
            )

        prefetched_labels = self._prefetch_patch_labels(normalized_labels)
        if prefetched_labels is None:
            for label in normalized_labels:
                add_label(id=entity_id, label_name=label)
            return

        pending_label_ids = []
        for label in normalized_labels:
            normalized_label = self._normalize_patch_label_value(label)
            label_data = prefetched_labels.get(normalized_label)
            if label_data is None:
                label_data = self.opencti.label.create(value=label)
                prefetched_labels[normalized_label] = label_data
            pending_label_ids.append(label_data["id"])
            if len(pending_label_ids) >= LABEL_RELATION_CREATE_BATCH_SIZE:
                self._flush_label_relation_batch(
                    entity_id,
                    pending_label_ids,
                    add_label,
                    add_many,
                )
                pending_label_ids = []
        self._flush_label_relation_batch(
            entity_id,
            pending_label_ids,
            add_label,
            add_many,
        )

    @staticmethod
    def _normalize_patch_label_value(value):
        return value.lower().strip() if isinstance(value, str) else value

    def _prefetch_patch_labels(self, labels):
        if len(labels) <= 1:
            return None

        unique_labels = []
        seen_labels = set()
        for label in labels:
            if label in seen_labels:
                continue
            seen_labels.add(label)
            unique_labels.append(label)

        try:
            prefetched_labels = {}
            for start_index in range(0, len(unique_labels), LABEL_PREFETCH_BATCH_SIZE):
                batch_labels = unique_labels[
                    start_index : start_index + LABEL_PREFETCH_BATCH_SIZE
                ]
                label_data_list = (
                    self.opencti.label.list(
                        filters={
                            "mode": "and",
                            "filters": [{"key": "value", "values": batch_labels}],
                            "filterGroups": [],
                        },
                        getAll=True,
                    )
                    or []
                )
                for label_data in label_data_list:
                    prefetched_labels[
                        self._normalize_patch_label_value(label_data["value"])
                    ] = label_data
            return prefetched_labels
        except Exception:
            return None

    @staticmethod
    def _flush_label_relation_batch(entity_id, label_ids, add_label, add_many):
        if len(label_ids) == 0:
            return
        if add_many is None or len(label_ids) == 1:
            for label_id in label_ids:
                add_label(id=entity_id, label_id=label_id)
            return
        add_many(entity_id, label_ids, "object-label")

    def remove_labels(self, entity_type, entity_id, labels, version=2):
        """Remove labels from an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param labels: List of labels to remove
        :type labels: list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        for label in labels:
            if version == 2:
                label = label["value"]
            if entity_type == "relationship":
                self.opencti.stix_core_relationship.remove_label(
                    id=entity_id, label_name=label
                )
            elif StixCyberObservableTypes.has_value(entity_type):
                self.opencti.stix_cyber_observable.remove_label(
                    id=entity_id, label_name=label
                )
            else:
                self.opencti.stix_domain_object.remove_label(
                    id=entity_id, label_name=label
                )

    def replace_created_by_ref(self, entity_type, entity_id, created_by_ref, version=2):
        """Replace the created_by reference of an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param created_by_ref: New created_by reference
        :type created_by_ref: str or list
        :param version: Version of the patch format (default: 2)
        :type version: int
        """
        if version == 2:
            created_by_ref = (
                created_by_ref[0]["value"] if created_by_ref is not None else None
            )
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_created_by(
                id=entity_id, identity_id=created_by_ref
            )
        elif entity_type == "sighting":
            self.opencti.stix_sighting_relationship.update_created_by(
                id=entity_id, identity_id=created_by_ref
            )
        elif StixCyberObservableTypes.has_value(entity_type):
            self.opencti.stix_cyber_observable.update_created_by(
                id=entity_id, identity_id=created_by_ref
            )
        else:
            self.opencti.stix_domain_object.update_created_by(
                id=entity_id, identity_id=created_by_ref
            )

    def update_attribute(self, entity_type, entity_id, field_input):
        """Update an attribute of an entity.

        :param entity_type: Type of the entity
        :type entity_type: str
        :param entity_id: ID of the entity
        :type entity_id: str
        :param field_input: Input containing the attribute update
        :type field_input: list
        """
        # Relations
        if entity_type == "relationship":
            self.opencti.stix_core_relationship.update_field(
                id=entity_id, input=field_input
            )
        elif entity_type == "sighting":
            self.opencti.stix_sighting_relationship.update_field(
                id=entity_id, input=field_input
            )
        # Observables
        elif StixCyberObservableTypes.has_value(entity_type):
            self.opencti.stix_cyber_observable.update_field(
                id=entity_id, input=field_input
            )
        # Meta
        elif entity_type == "marking-definition":
            self.opencti.marking_definition.update_field(
                id=entity_id, input=field_input
            )
        elif entity_type == "label":
            self.opencti.label.update_field(id=entity_id, input=field_input)
        elif entity_type == "vocabulary":
            self.opencti.vocabulary.update_field(id=entity_id, input=field_input)
        elif entity_type == "kill-chain-phase":
            self.opencti.kill_chain_phase.update_field(id=entity_id, input=field_input)
        elif entity_type == "external-reference":
            self.opencti.external_reference.update_field(
                id=entity_id, input=field_input
            )
        # Remaining stix domain
        else:
            self.opencti.stix_domain_object.update_field(
                id=entity_id, input=field_input
            )

    def process_update(self, data):
        """Process a STIX2 patch/update operation.

        :param data: Data containing x_opencti_patch operations
        :type data: dict
        """
        try:
            # Build the inputs for update api
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
                        if isinstance(current_val, list):
                            values = list(
                                map(
                                    lambda x: (
                                        x["value"]
                                        if (isinstance(x, dict) and "value" in x)
                                        else x
                                    ),
                                    current_val,
                                )
                            )
                            inputs.append({"key": key, "value": values})
                        else:
                            values = (
                                current_val["value"]
                                if (
                                    isinstance(current_val, dict)
                                    and "value" in current_val
                                )
                                else str(current_val)
                            )
                            inputs.append({"key": key, "value": values})
            self.update_attribute(data["type"], data["id"], inputs)
        except Exception as err:
            self.opencti.app_logger.error(str(err))
