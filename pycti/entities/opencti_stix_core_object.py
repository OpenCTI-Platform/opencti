# coding: utf-8


class StixCoreObject:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file

    """
        Update a Stix-Domain-Object object field

        :param id: the Stix-Domain-Object id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Domain-Object object
    """

    def merge(self, **kwargs):
        id = kwargs.get("id", None)
        stix_core_objects_ids = kwargs.get("object_ids", None)
        if id is not None and stix_core_objects_ids is not None:
            self.opencti.log(
                "info",
                "Merging Core object {"
                + id
                + "} with {"
                + ",".join(stix_core_objects_ids)
                + "}.",
            )
            query = """
                    mutation StixCoreObjectEdit($id: ID!, $stixCoreObjectsIds: [String]!) {
                        stixCoreObjectEdit(id: $id) {
                            merge(stixCoreObjectsIds: $stixCoreObjectsIds) {
                                id
                                standard_id
                                entity_type
                            }
                        }
                    }
                """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixCoreObjectsIds": stix_core_objects_ids,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixCoreObjectEdit"]["merge"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_core_object] Missing parameters: id and object_ids",
            )
            return None

    def list_files(self, **kwargs):
        id = kwargs.get("id", None)
        self.opencti.log(
            "info",
            "Listing files of Stix-Core-Object { " + id + " }",
        )
        query = """
                    query StixCoreObject($id: String!) {
                        stixCoreObject(id: $id) {
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
                """
        result = self.opencti.query(query, {"id": id})
        entity = self.opencti.process_multiple_fields(result["data"]["stixCoreObject"])
        return entity["importFiles"]

    """
        Get the reports about a Stix-Core-Object object

        :param id: the id of the Stix-Core-Object
        :return List of reports
    """

    def reports(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Getting reports of the Stix-Core-Object {" + id + "}.",
            )
            query = """
                query StixCoreObject($id: String!) {
                    stixCoreObject(id: $id) {
                        reports {
                            edges {
                                node {
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
                                                edges {
                                                    node {
                                                        id
                                                        value
                                                        color
                                                    }
                                                }
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
                                    objectMarking {
                                        edges {
                                            node {
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
                                        }
                                    }
                                    objectLabel {
                                        edges {
                                            node {
                                                id
                                                value
                                                color
                                            }
                                        }
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
                                    report_types
                                    published                             
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixCoreObject"]
            )
            if processed_result:
                return processed_result["reports"]
            else:
                return []
        else:
            self.opencti.log("error", "Missing parameters: id")
            return None
