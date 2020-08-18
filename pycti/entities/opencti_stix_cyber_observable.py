# coding: utf-8

import json


class StixCyberObservable:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
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
                    name
                    aliases
                    description
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
                    }
                }
            }
            observable_value
            ... on AutonomousSystem {
                number
                name
                rir
            }
            ... on Directory {
                path
                path_enc
                ctime
                mtime
                atime
            }
            ... on DomainName {
                value
            }
            ... on EmailAddr {
                value
                display_name
            }
            ... on EmailMessage {
                is_multipart
                attribute_date
                content_type
                message_id
                subject
                received_lines
                body
            }
            ... on HashedObservable {
                md5
                sha1
                sha256
                sha512                
            }
            ... on Artifact {
                mime_type
                payload_bin
                url
                encryption_algorithm
                decryption_key
            }        
            ... on StixFile {
                extensions
                size
                name
                name_enc
                magic_number_hex
                mime_type
                ctime
                mtime
                atime
            }
            ... on X509Certificate {
                is_self_signed
                version
                serial_number
                signature_algorithm
                issuer
                validity_not_before
                validity_not_after
            }
            ... on IPv4Addr {
                value
            }
            ... on IPv6Addr {
                value
            }
            ... on MacAddr {
                value
            }
            ... on Mutex {
                name            
            }
            ... on NetworkTraffic {
                extensions
                start
                end
                is_active
                src_port
                dst_port
                protocols
                src_byte_count
                dst_byte_count
                src_packets
                dst_packets
            }
            ... on Process {
                extensions
                is_hidden
                pid
                created_time
                cwd
                command_line
                environment_variables
            }
            ... on Software {
                name
                cpe
                swid
                languages
                vendor
                version
            }
            ... on Url {
                value
            }
            ... on UserAccount {
                extensions
                user_id
                credential
                account_login
                account_type
                display_name
                is_service_account
                is_privileged
                can_escalate_privs
                is_disabled
                account_created
                account_expires
                credential_last_changed
                account_first_login
                account_last_login
            }
            WindowsRegistryKey {
                attribute_key
                modified_time
                number_of_subkeys
            }
            WindowsRegistryValueType {
                name
                data
                data_type
            }
            X509V3ExtensionsType {
                basic_constraints
                name_constraints
                policy_constraints
                key_usage
                extended_key_usage
                subject_key_identifier
                authority_key_identifier
                subject_alternative_name
                issuer_alternative_name
                subject_directory_attributes
                crl_distribution_points
                inhibit_any_policy
                private_key_usage_period_not_before
                private_key_usage_period_not_after
                certificate_policies
                policy_mappings
            }
            XOpenCTICryptographicKey {
                value
            }
            XOpenCTICryptocurrencyWallet {
                value
            }
            XOpenCTIText {
                value
            }
            XOpenCTIUserAgent {
                value
            }
        """

    """
        List StixCyberObservable objects

        :param types: the array of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row
        :return List of StixCyberObservable objects
    """

    def list(self, **kwargs):
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info",
            "Listing StixCyberObservables with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
            query StixCyberObservables($types: [String], $filters: [StixCyberObservablesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {
                StixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }                    
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "types": types,
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )

        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["StixCyberObservables"])
            final_data = final_data + data
            while result["data"]["StixCyberObservables"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["StixCyberObservables"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing StixCyberObservables after " + after)
                result = self.opencti.query(
                    query,
                    {
                        "types": types,
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["StixCyberObservables"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["StixCyberObservables"], with_pagination
            )

    """
        Read a StixCyberObservable object

        :param id: the id of the StixCyberObservable
        :param filters: the filters to apply if no id provided
        :return StixCyberObservable object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading StixCyberObservable {" + id + "}.")
            query = (
                """
                query StixCyberObservable($id: String!) {
                    StixCyberObservable(id: $id) {
                        """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else self.properties
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["StixCyberObservable"]
            )
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_cyber_observable] Missing parameters: id or filters",
            )
            return None

    """
        Create a Stix-Observable object

        :param observableData: the data of the observable (STIX2 structure)
        :return Stix-Observable object
    """

    def create(self, **kwargs):
        observable_data = kwargs.get("observableData", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        create_indicator = (
            observable_data["x_opencti_create_indicator"]
            if "x_opencti_create_indicator" in observable_data
            else kwargs.get("createIndicator", False)
        )
        type = observable_data["type"].capitalize()
        if type.lower() == "file":
            type = "StixFile"
        if type is not None:
            self.opencti.log(
                "info",
                "Creating Stix-Cyber-Observable {"
                + type
                + "} with indicator at "
                + str(create_indicator)
                + ".",
            )
            input_variables = {
                "type": type,
                "stix_id": observable_data["id"] if "id" in observable_data else None,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectLabel": object_label,
                "externalReferences": external_references,
                "created": (
                    observable_data["created"]
                    if "created" in observable_data
                    else None,
                ),
                "modified": (
                    observable_data["modified"]
                    if "modified" in observable_data
                    else None,
                ),
                "createIndicator": create_indicator,
            }
            query = """
                mutation StixCyberObservableAdd(
                    $type: String!,
                    $AutonomousSystem: AutonomousSystemAddInput,
                    $Directory: DirectoryAddInput,
                    $DomainName: DomainNameAddInput,
                    $EmailAddr: EmailAddrAddInput,
                    $EmailMessage: EmailMessageAddInput,
                    $EmailMimePartType: EmailMimePartTypeAddInput,
                    $Artifact: ArtifactAddInput,
                    $StixFile: StixFileAddInput,
                    $X509Certificate: X509CertificateAddInput,
                    $IPv4Addr: IPv4AddrAddInput,
                    $IPv6Addr: IPv6AddrAddInput,
                    $MacAddr: MacAddrAddInput,
                    $Mutex: MutexAddInput,
                    $NetworkTraffic: NetworkTrafficAddInput,
                    $Process: ProcessAddInput,
                    $Software: SoftwareAddInput,
                    $Url: UrlAddInput,
                    $UserAccount: UserAccountAddInput,
                    $WindowsRegistryKey: WindowsRegistryKeyAddInput,
                    $WindowsRegistryValueType: WindowsRegistryValueTypeAddInput,
                    $X509V3ExtensionsType: X509V3ExtensionsTypeAddInput,
                    $XOpenCTICryptographicKey: XOpenCTICryptographicKeyAddInput,
                    $XOpenCTICryptocurrencyWallet: XOpenCTICryptocurrencyWalletAddInput,
                    $XOpenCTIText: XOpenCTITextAddInput,
                    $XOpenCTIUserAgent: XOpenCTIUserAgentAddInput
                    $createIndicator: Boolean
                ) {
                    stixCyberObservableAdd(
                        type: $type,
                        AutonomousSystem: $AutonomousSystem,
                        Directory: $Directory,
                        DomainName: $DomainName,
                        EmailAddr: $EmailAddr,
                        EmailMessage: $EmailMessage,
                        EmailMimePartType: $EmailMimePartType,
                        Artifact: $Artifact,
                        StixFile: $StixFile,
                        X509Certificate: $X509Certificate,
                        IPv4Addr: $IPv4Addr,
                        IPv6Addr: $IPv6Addr,
                        MacAddr: $MacAddr,
                        Mutex: $Mutex,
                        NetworkTraffic: $NetworkTraffic,
                        Process: $Process,
                        Software: $Software,
                        Url: $Url,
                        UserAccount: $UserAccount,
                        WindowsRegistryKey: $WindowsRegistryKey,
                        WindowsRegistryValueType: $WindowsRegistryValueType,
                        X509V3ExtensionsType: $X509V3ExtensionsType,
                        XOpenCTICryptographicKey: $XOpenCTICryptographicKey,
                        XOpenCTICryptocurrencyWallet: $XOpenCTICryptocurrencyWallet,
                        XOpenCTIText: $XOpenCTIText,
                        XOpenCTIUserAgent: $XOpenCTIUserAgent
                        createIndicator: $createIndicator
                    ) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            if type == "Autonomous-System":
                input_variables["AutonomousSystem"] = {
                    "number": observable_data["number"],
                    "name": observable_data["name"]
                    if "name" in observable_data
                    else None,
                    "rir": observable_data["rir"] if "rir" in observable_data else None,
                }
            elif type == "Directory":
                input_variables["Directory"] = {
                    "path": observable_data["path"],
                    "path_enc": observable_data["path_enc"]
                    if "path_enc" in observable_data
                    else None,
                    "ctime": observable_data["ctime"]
                    if "ctime" in observable_data
                    else None,
                    "mtime": observable_data["mtime"]
                    if "mtime" in observable_data
                    else None,
                    "atime": observable_data["atime"]
                    if "atime" in observable_data
                    else None,
                }
            elif type == "Domain-Name":
                input_variables["DomainName"] = {"value": observable_data["value"]}
            elif type == "Email-Addr":
                input_variables["EmailAddr"] = {
                    "value": observable_data["value"],
                    "display_name": observable_data["display_name"]
                    if "display_name" in observable_data
                    else None,
                }
            elif type == "Email-Message":
                input_variables["EmailMessage"] = {
                    "is_multipart": observable_data["is_multipart"]
                    if "is_multipart" in observable_data
                    else None,
                    "display_name": observable_data["display_name"]
                    if "display_name" in observable_data
                    else None,
                    "attribute_date": observable_data["attribute_date"]
                    if "date" in observable_data
                    else None,
                    "message_id": observable_data["message_id"]
                    if "message_id" in observable_data
                    else None,
                    "subject": observable_data["subject"]
                    if "subject" in observable_data
                    else None,
                    "received_lines": observable_data["received_lines"]
                    if "received_lines" in observable_data
                    else None,
                    "body": observable_data["body"]
                    if "body" in observable_data
                    else None,
                }
            elif type == "Email-Mime-Part-Type":
                input_variables["EmailMimePartType"] = {
                    "body": observable_data["body"]
                    if "body" in observable_data
                    else None,
                    "content_type": observable_data["content_type"]
                    if "content_type" in observable_data
                    else None,
                    "content_disposition": observable_data["content_disposition"]
                    if "content_disposition" in observable_data
                    else None,
                }
            elif type == "Artifact":
                input_variables["Artifact"] = {
                    "md5": observable_data["hashes"]["MD5"]
                    if "hashes" in observable_data
                    and "MD5" in observable_data["hashes"]
                    else None,
                    "sha1": observable_data["hashes"]["SHA-1"]
                    if "hashes" in observable_data
                    and "SHA-1" in observable_data["hashes"]
                    else None,
                    "sha256": observable_data["hashes"]["SHA-256"]
                    if "hashes" in observable_data
                    and "SHA-256" in observable_data["hashes"]
                    else None,
                    "sha512": observable_data["hashes"]["SHA-512"]
                    if "hashes" in observable_data
                    and "SHA-512" in observable_data["hashes"]
                    else None,
                    "mime_type": observable_data["mime_type"]
                    if "mime_type" in observable_data
                    else None,
                    "payload_bin": observable_data["payload_bin"]
                    if "payload_bin" in observable_data
                    else None,
                    "url": observable_data["url"] if "url" in observable_data else None,
                    "encryption_algorithm": observable_data["encryption_algorithm"]
                    if "encryption_algorithm" in observable_data
                    else None,
                    "decryption_key": observable_data["decryption_key"]
                    if "decryption_key" in observable_data
                    else None,
                }
            elif type == "StixFile":
                input_variables["StixFile"] = {
                    "md5": observable_data["hashes"]["MD5"]
                    if "hashes" in observable_data
                    and "MD5" in observable_data["hashes"]
                    else None,
                    "sha1": observable_data["hashes"]["SHA-1"]
                    if "hashes" in observable_data
                    and "SHA-1" in observable_data["hashes"]
                    else None,
                    "sha256": observable_data["hashes"]["SHA-256"]
                    if "hashes" in observable_data
                    and "SHA-256" in observable_data["hashes"]
                    else None,
                    "sha512": observable_data["hashes"]["SHA-512"]
                    if "hashes" in observable_data
                    and "SHA-512" in observable_data["hashes"]
                    else None,
                    "extensions": observable_data["extensions"]
                    if "extensions" in observable_data
                    else None,
                    "size": observable_data["size"]
                    if "size" in observable_data
                    else None,
                    "name": observable_data["name"]
                    if "name" in observable_data
                    else None,
                    "name_enc": observable_data["name_enc"]
                    if "name_enc" in observable_data
                    else None,
                    "magic_number_hex": observable_data["magic_number_hex"]
                    if "magic_number_hex" in observable_data
                    else None,
                    "mime_type": observable_data["mime_type"]
                    if "mime_type" in observable_data
                    else None,
                    "mtime": observable_data["mtime"]
                    if "mtime" in observable_data
                    else None,
                    "ctime": observable_data["ctime"]
                    if "ctime" in observable_data
                    else None,
                    "atime": observable_data["atime"]
                    if "atime" in observable_data
                    else None,
                }
            result = self.opencti.query(query, input_variables)
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableAdd"]
            )
        else:
            self.opencti.log("error", "Missing parameters: type")

    """
        Update a Stix-Observable object field

        :param id: the Stix-Observable id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Observable object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating Stix-Observable {" + id + "} field {" + key + "}."
            )
            query = """
                mutation StixCyberObservableEdit($id: ID!, $input: EditInput!) {
                    StixCyberObservableEdit(id: $id) {
                        fieldPatch(input: $input) {
                            id
                        }
                    }
                }
            """
            result = self.opencti.query(
                query, {"id": id, "input": {"key": key, "value": value}}
            )
            return self.opencti.process_multiple_fields(
                result["data"]["StixCyberObservableEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_cyber_observable_update_field] Missing parameters: id and key and value",
            )
            return None

    """
        Delete a Stix-Observable

        :param id: the Stix-Observable id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log("info", "Deleting Stix-Observable {" + id + "}.")
            query = """
                 mutation StixCyberObservableEdit($id: ID!) {
                     StixCyberObservableEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log(
                "error", "[opencti_stix_cyber_observable_delete] Missing parameters: id"
            )
            return None

    """
        Update the Identity author of a Stix-Observable object (created_by)

        :param id: the id of the Stix-Observable
        :param identity_id: the id of the Identity
        :return Boolean
    """

    def update_created_by(self, **kwargs):
        id = kwargs.get("id", None)
        opencti_stix_object_or_stix_relationship = kwargs.get("entity", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None and identity_id is not None:
            if opencti_stix_object_or_stix_relationship is None:
                custom_attributes = """
                    id
                    createdBy {
                        node {
                            id
                            entity_type
                            stix_id
                            stix_label
                            name
                            alias
                            description
                            created
                            modified
                            ... on Organization {
                                x_opencti_organization_type
                            }
                        }
                        relation {
                            id
                        }
                    }    
                """
                opencti_stix_object_or_stix_relationship = self.read(
                    id=id, customAttributes=custom_attributes
                )
            if opencti_stix_object_or_stix_relationship is None:
                self.opencti.log("error", "Cannot update created_by, entity not found")
                return False
            current_identity_id = None
            current_relation_id = None
            if opencti_stix_object_or_stix_relationship["createdBy"] is not None:
                current_identity_id = opencti_stix_object_or_stix_relationship[
                    "createdBy"
                ]["id"]
                current_relation_id = opencti_stix_object_or_stix_relationship[
                    "createdBy"
                ]["remote_relation_id"]
            # Current identity is the same
            if current_identity_id == identity_id:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Updating author of Stix-Entity {"
                    + id
                    + "} with Identity {"
                    + identity_id
                    + "}",
                )
                # Current identity is different, delete the old relation
                if current_relation_id is not None:
                    query = """
                        mutation StixCyberObservableEdit($id: ID!, $relationId: ID!) {
                            StixCyberObservableEdit(id: $id) {
                                relationDelete(relationId: $relationId) {
                                    id
                                }
                            }
                        }
                    """
                    self.opencti.query(
                        query, {"id": id, "relationId": current_relation_id}
                    )
                # Add the new relation
                query = """
                   mutation StixCyberObservableEdit($id: ID!, $input: StixMetaRelationshipAddInput) {
                       StixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                variables = {
                    "id": id,
                    "input": {
                        "fromRole": "so",
                        "toId": identity_id,
                        "toRole": "creator",
                        "through": "created_by",
                    },
                }
                self.opencti.query(query, variables)

        else:
            self.opencti.log("error", "Missing parameters: id and identity_id")
            return False
