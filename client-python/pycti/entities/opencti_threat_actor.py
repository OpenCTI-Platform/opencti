# coding: utf-8

import uuid
import warnings

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities.base import Entity
from pycti.entities.opencti_threat_actor_group import ThreatActorGroup
from pycti.entities.opencti_threat_actor_individual import ThreatActorIndividual


class ThreatActor(Entity):
    """Main ThreatActor class for OpenCTI

    Manages threat actor entities (groups and individuals) in the OpenCTI platform.
    """

    PROPERTIES = """
        id
        standard_id
        entity_type
        parent_types
        spec_version
        created_at
        updated_at
        createdBy {
            ... on Identity {
                id
                standard_id
                entity_type
                parent_types
                spec_version
                identity_class
                name
                description
                roles
                contact_information
                x_opencti_aliases
                created
                modified
                objectLabel {
                    id
                    value
                    color
                }
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
        }
        objectOrganization {
            id
            standard_id
            name
        }
        objectMarking {
            id
            standard_id
            entity_type
            definition_type
            definition
            created
            modified
            x_opencti_order
            x_opencti_color
        }
        objectLabel {
            id
            value
            color
        }
        externalReferences {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    source_name
                    description
                    url
                    hash
                    external_id
                    created
                    modified
                    importFiles {
                        edges {
                            node {
                                id
                                name
                                size
                                metaData {
                                    mimetype
                                    version
                                }
                            }
                        }
                    }
                }
            }
        }
        revoked
        confidence
        created
        modified
        name
        description
        aliases
        threat_actor_types
        first_seen
        last_seen
        roles
        goals
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
    """

    FILES_PROPERTIES = """
        id
        name
        size
        metaData {
            mimetype
            version
        }
        objectMarking {
            id
            standard_id
            entity_type
            definition_type
            definition
            created
            modified
            x_opencti_order
            x_opencti_color
        }
    """

    def __init__(self, opencti, *args, **kwargs):
        super().__init__(opencti, *args, **kwargs)
        self.threat_actor_group = ThreatActorGroup(opencti)
        self.threat_actor_individual = ThreatActorIndividual(opencti)

    @staticmethod
    def generate_id(name, opencti_type):
        """Generate a STIX ID for a Threat Actor.

        :param name: the name of the Threat Actor
        :type name: str
        :param opencti_type: the type of the Threat Actor (e.g., 'Threat-Actor-Group')
        :type opencti_type: str
        :return: STIX ID for the Threat Actor
        :rtype: str
        """
        data = {"name": name.lower().strip(), "opencti_type": opencti_type}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "threat-actor--" + id

    def generate_id_from_data(self, data):
        """Generate a STIX ID from Threat Actor data.

        :param data: Dictionary containing 'name' and optionally 'x_opencti_type' keys
        :type data: dict
        :return: STIX ID for the Threat Actor
        :rtype: str
        """
        data_type = "Threat-Actor-Group"
        if "x_opencti_type" in data:
            data_type = data["x_opencti_type"]
        elif self.opencti.get_attribute_in_extension("type", data) is not None:
            data_type = self.opencti.get_attribute_in_extension("type", data)
        return ThreatActor.generate_id(data["name"], data_type)

    def create(self, **kwargs):
        """Create a Threat-Actor-Group object (deprecated).

        .. deprecated::
            Use :meth:`threat_actor_group.create` or :meth:`threat_actor_individual.create` instead.
        """
        warnings.warn(
            "ThreatActor.create() is deprecated, use threat_actor_group.create() "
            "or threat_actor_individual.create() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.threat_actor_group.create(**kwargs)

    def import_from_stix2(self, **kwargs):
        """Import a Threat-Actor object from a STIX2 object.

        :param stixObject: the STIX2 Threat-Actor object
        :type stixObject: dict
        :return: Threat-Actor object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        if "x_opencti_type" in stix_object:
            type = stix_object["x_opencti_type"].lower()
        elif self.opencti.get_attribute_in_extension("type", stix_object) is not None:
            type = self.opencti.get_attribute_in_extension("type", stix_object).lower()
        elif (
            "resource_level" in stix_object
            and stix_object["resource_level"].lower() == "individual"
        ):
            type = "threat-actor-individual"
        else:
            type = "threat-actor-group"

        if type == "threat-actor-individual":
            return self.threat_actor_individual.import_from_stix2(**kwargs)
        else:
            return self.threat_actor_group.import_from_stix2(**kwargs)
