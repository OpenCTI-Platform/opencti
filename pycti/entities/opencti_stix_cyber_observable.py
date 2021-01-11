# coding: utf-8

import json


class StixCyberObservable:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file
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
                    }
                }
            }
            observable_value
            x_opencti_description
            x_opencti_score
            indicators {
                edges {
                    node {
                        id
                        pattern
                        pattern_type
                    }
                }
            }
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
            ... on Artifact {
                mime_type
                payload_bin
                url
                encryption_algorithm
                decryption_key
                hashes {
                  algorithm
                  hash
                }           
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
                x_opencti_additional_names
                hashes {
                  algorithm
                  hash
                }           
            }
            ... on X509Certificate {
                is_self_signed
                version
                serial_number
                signature_algorithm
                issuer
                subject
                subject_public_key_algorithm
                subject_public_key_modulus
                subject_public_key_exponent
                validity_not_before
                validity_not_after
                hashes {
                  algorithm
                  hash
                }        
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
            ... on WindowsRegistryKey {
                attribute_key
                modified_time
                number_of_subkeys
            }
            ... on WindowsRegistryValueType {
                name
                data
                data_type
            }
            ... on X509V3ExtensionsType {
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
            ... on XOpenCTICryptographicKey {
                value
            }
            ... on XOpenCTICryptocurrencyWallet {
                value
            }
            ... on XOpenCTIText {
                value
            }
            ... on XOpenCTIUserAgent {
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
                stixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["stixCyberObservables"])
            final_data = final_data + data
            while result["data"]["stixCyberObservables"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixCyberObservables"]["pageInfo"]["endCursor"]
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
                    result["data"]["stixCyberObservables"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixCyberObservables"], with_pagination
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
                    stixCyberObservable(id: $id) {
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
                result["data"]["stixCyberObservable"]
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
        observable_data = kwargs.get("observableData", {})
        simple_observable_id = kwargs.get("simple_observable_id", None)
        simple_observable_key = kwargs.get("simple_observable_key", None)
        simple_observable_value = kwargs.get("simple_observable_value", None)
        simple_observable_description = kwargs.get(
            "simple_observable_description", None
        )
        x_opencti_score = kwargs.get("x_opencti_score", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        update = kwargs.get("update", False)

        create_indicator = (
            observable_data["x_opencti_create_indicator"]
            if "x_opencti_create_indicator" in observable_data
            else kwargs.get("createIndicator", False)
        )
        attribute = None
        if simple_observable_key is not None:
            key_split = simple_observable_key.split(".")
            type = key_split[0].title()
            attribute = key_split[1]
            if attribute not in ["hashes", "extensions"]:
                observable_data[attribute] = simple_observable_value
        else:
            type = (
                observable_data["type"].title() if "type" in observable_data else None
            )
        if type is None:
            return
        if type.lower() == "file":
            type = "StixFile"
        elif type.lower() == "ipv4-addr":
            type = "IPv4-Addr"
        elif type.lower() == "ipv6-addr":
            type = "IPv6-Addr"
        elif type.lower() == "x-opencti-hostname":
            type = "X-OpenCTI-Hostname"
        elif type.lower() == "x-opencti-cryptocurrency-wallet":
            type = "X-OpenCTI-Cryptocurrency-Wallet"
        elif type.lower() == "x-opencti-user-agent":
            type = "X-OpenCTI-User-Agent"
        elif type.lower() == "x-opencti-cryptographic-key":
            type = "X-OpenCTI-Cryptographic-Key"
        elif type.lower() == "x-opencti-text":
            type = "X-OpenCTI-text"

        x_opencti_description = (
            observable_data["x_opencti_description"]
            if "x_opencti_description" in observable_data
            else None
        )
        if simple_observable_description is not None:
            x_opencti_description = simple_observable_description
        x_opencti_score = (
            observable_data["x_opencti_score"]
            if "x_opencti_score" in observable_data
            else x_opencti_score
        )
        if simple_observable_description is not None:
            x_opencti_description = simple_observable_description

        stix_id = observable_data["id"] if "id" in observable_data else None
        if simple_observable_id is not None:
            stix_id = simple_observable_id

        hashes = []
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.md5"
        ):
            hashes.append({"algorithm": "MD5", "hash": simple_observable_value})
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.sha-1"
        ):
            hashes.append({"algorithm": "SHA-1", "hash": simple_observable_value})
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.sha-256"
        ):
            hashes.append({"algorithm": "SHA-256", "hash": simple_observable_value})
        if "hashes" in observable_data:
            for key, value in observable_data["hashes"].items():
                hashes.append({"algorithm": key, "hash": value})

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
                "stix_id": stix_id,
                "x_opencti_score": x_opencti_score,
                "x_opencti_description": x_opencti_description,
                "createIndicator": create_indicator,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectLabel": object_label,
                "externalReferences": external_references,
                "update": update,
            }
            query = """
                mutation StixCyberObservableAdd(
                    $type: String!,
                    $stix_id: String,
                    $x_opencti_score: Int,
                    $x_opencti_description: String,
                    $createIndicator: Boolean,
                    $createdBy: String,
                    $objectMarking: [String],
                    $objectLabel: [String],
                    $externalReferences: [String],                    
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
                    $XOpenCTIHostname: XOpenCTIHostnameAddInput
                    $XOpenCTIText: XOpenCTITextAddInput,
                    $XOpenCTIUserAgent: XOpenCTIUserAgentAddInput
                ) {
                    stixCyberObservableAdd(
                        type: $type,
                        stix_id: $stix_id,
                        x_opencti_score: $x_opencti_score,
                        x_opencti_description: $x_opencti_description,
                        createIndicator: $createIndicator,
                        createdBy: $createdBy,
                        objectMarking: $objectMarking,
                        objectLabel: $objectLabel,
                        externalReferences: $externalReferences,             
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
                        XOpenCTIHostname: $XOpenCTIHostname,
                        XOpenCTIText: $XOpenCTIText,
                        XOpenCTIUserAgent: $XOpenCTIUserAgent
                    ) {
                        id
                        standard_id
                        entity_type
                        parent_types
                        indicators {
                            edges {
                                node {
                                    id
                                    pattern
                                    pattern_type
                                }
                            }
                        }
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
                if attribute is not None:
                    input_variables["DomainName"][attribute] = simple_observable_value
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
                    "hashes": hashes if len(hashes) > 0 else None,
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
                    "hashes": hashes if len(hashes) > 0 else None,
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
                    "x_opencti_additional_names": observable_data[
                        "x_opencti_additional_names"
                    ]
                    if "x_opencti_additional_names" in observable_data
                    else None,
                }
            elif type == "X509-Certificate":
                input_variables["X509Certificate"] = {
                    "hashes": hashes if len(hashes) > 0 else None,
                    "is_self_signed": observable_data["is_self_signed"]
                    if "is_self_signed" in observable_data
                    else False,
                    "version": observable_data["version"]
                    if "version" in observable_data
                    else None,
                    "serial_number": observable_data["serial_number"]
                    if "serial_number" in observable_data
                    else None,
                    "signature_algorithm": observable_data["signature_algorithm"]
                    if "signature_algorithm" in observable_data
                    else None,
                    "issuer": observable_data["issuer"]
                    if "issuer" in observable_data
                    else None,
                    "validity_not_before": observable_data["validity_not_before"]
                    if "validity_not_before" in observable_data
                    else None,
                    "validity_not_after": observable_data["validity_not_after"]
                    if "validity_not_after" in observable_data
                    else None,
                    "subject": observable_data["subject"]
                    if "subject" in observable_data
                    else None,
                    "subject_public_key_algorithm": observable_data[
                        "subject_public_key_algorithm"
                    ]
                    if "subject_public_key_algorithm" in observable_data
                    else None,
                    "subject_public_key_modulus": observable_data[
                        "subject_public_key_modulus"
                    ]
                    if "subject_public_key_modulus" in observable_data
                    else None,
                    "subject_public_key_exponent": observable_data[
                        "subject_public_key_exponent"
                    ]
                    if "subject_public_key_exponent" in observable_data
                    else None,
                }
            elif type == "IPv4-Addr":
                input_variables["IPv4Addr"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "IPv6-Addr":
                input_variables["IPv6Addr"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "Mac-Addr":
                input_variables["MacAddr"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "Mutex":
                input_variables["Mutex"] = {
                    "name": observable_data["name"]
                    if "name" in observable_data
                    else None,
                }
            elif type == "Network-Traffic":
                input_variables["NetworkTraffic"] = {
                    "extensions": observable_data["extensions"]
                    if "extensions" in observable_data
                    else None,
                    "start": observable_data["start"]
                    if "start" in observable_data
                    else None,
                    "end": observable_data["end"] if "end" in observable_data else None,
                    "is_active": observable_data["is_active"]
                    if "is_active" in observable_data
                    else None,
                    "src_port": observable_data["src_port"]
                    if "src_port" in observable_data
                    else None,
                    "dst_port": observable_data["dst_port"]
                    if "dst_port" in observable_data
                    else None,
                    "protocols": observable_data["protocols"]
                    if "protocols" in observable_data
                    else None,
                    "src_byte_count": observable_data["src_byte_count"]
                    if "src_byte_count" in observable_data
                    else None,
                    "dst_byte_count": observable_data["dst_byte_count"]
                    if "dst_byte_count" in observable_data
                    else None,
                    "src_packets": observable_data["src_packets"]
                    if "src_packets" in observable_data
                    else None,
                    "dst_packets": observable_data["dst_packets"]
                    if "dst_packets" in observable_data
                    else None,
                }
            elif type == "Process":
                input_variables["Process"] = {
                    "extensions": observable_data["extensions"]
                    if "extensions" in observable_data
                    else None,
                    "is_hidden": observable_data["is_hidden"]
                    if "is_hidden" in observable_data
                    else None,
                    "pid": observable_data["pid"] if "pid" in observable_data else None,
                    "created_time": observable_data["created_time"]
                    if "created_time" in observable_data
                    else None,
                    "cwd": observable_data["cwd"] if "cwd" in observable_data else None,
                    "command_line": observable_data["command_line"]
                    if "command_line" in observable_data
                    else None,
                    "environment_variables": observable_data["environment_variables"]
                    if "environment_variables" in observable_data
                    else None,
                }
            elif type == "Software":
                input_variables["Software"] = {
                    "name": observable_data["name"]
                    if "name" in observable_data
                    else None,
                    "cpe": observable_data["cpe"] if "cpe" in observable_data else None,
                    "swid": observable_data["swid"]
                    if "swid" in observable_data
                    else None,
                    "languages": observable_data["languages"]
                    if "languages" in observable_data
                    else None,
                    "vendor": observable_data["vendor"]
                    if "vendor" in observable_data
                    else None,
                    "version": observable_data["version"]
                    if "version" in observable_data
                    else None,
                }
            elif type == "Url":
                input_variables["Url"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "User-Account":
                input_variables["UserAccount"] = {
                    "extensions": observable_data["extensions"]
                    if "extensions" in observable_data
                    else None,
                    "user_id": observable_data["user_id"]
                    if "user_id" in observable_data
                    else None,
                    "credential": observable_data["credential"]
                    if "credential" in observable_data
                    else None,
                    "account_login": observable_data["account_login"]
                    if "account_login" in observable_data
                    else None,
                    "account_type": observable_data["account_type"]
                    if "account_type" in observable_data
                    else None,
                    "display_name": observable_data["display_name"]
                    if "display_name" in observable_data
                    else None,
                    "is_service_account": observable_data["is_service_account"]
                    if "is_service_account" in observable_data
                    else None,
                    "is_privileged": observable_data["is_privileged"]
                    if "is_privileged" in observable_data
                    else None,
                    "can_escalate_privs": observable_data["can_escalate_privs"]
                    if "can_escalate_privs" in observable_data
                    else None,
                    "is_disabled": observable_data["is_disabled"]
                    if "is_disabled" in observable_data
                    else None,
                    "account_created": observable_data["account_created"]
                    if "account_created" in observable_data
                    else None,
                    "account_expires": observable_data["account_expires"]
                    if "account_expires" in observable_data
                    else None,
                    "credential_last_changed": observable_data[
                        "credential_last_changed"
                    ]
                    if "credential_last_changed" in observable_data
                    else None,
                    "account_first_login": observable_data["account_first_login"]
                    if "account_first_login" in observable_data
                    else None,
                    "account_last_login": observable_data["account_last_login"]
                    if "account_last_login" in observable_data
                    else None,
                }
            elif type == "Windows-Registry-Key":
                input_variables["WindowsRegistryKey"] = {
                    "attribute_key": observable_data["key"]
                    if "key" in observable_data
                    else None,
                    "modified_time": observable_data["modified_time"]
                    if "modified_time" in observable_data
                    else None,
                    "number_of_subkeys": observable_data["number_of_subkeys"]
                    if "number_of_subkeys" in observable_data
                    else None,
                }
                print(input_variables)
            elif type == "Windows-Registry-Value-Type":
                input_variables["WindowsRegistryKeyValueType"] = {
                    "name": observable_data["name"]
                    if "name" in observable_data
                    else None,
                    "data": observable_data["data"]
                    if "data" in observable_data
                    else None,
                    "data_type": observable_data["data_type"]
                    if "data_type" in observable_data
                    else None,
                }
            elif type == "X509-V3-Extensions-Type":
                input_variables["X509V3ExtensionsType"] = {
                    "basic_constraints": observable_data["basic_constraints"]
                    if "basic_constraints" in observable_data
                    else None,
                    "name_constraints": observable_data["name_constraints"]
                    if "name_constraints" in observable_data
                    else None,
                    "policy_constraints": observable_data["policy_constraints"]
                    if "policy_constraints" in observable_data
                    else None,
                    "key_usage": observable_data["key_usage"]
                    if "key_usage" in observable_data
                    else None,
                    "extended_key_usage": observable_data["extended_key_usage"]
                    if "extended_key_usage" in observable_data
                    else None,
                    "subject_key_identifier": observable_data["subject_key_identifier"]
                    if "subject_key_identifier" in observable_data
                    else None,
                    "authority_key_identifier": observable_data[
                        "authority_key_identifier"
                    ]
                    if "authority_key_identifier" in observable_data
                    else None,
                    "subject_alternative_name": observable_data[
                        "subject_alternative_name"
                    ]
                    if "subject_alternative_name" in observable_data
                    else None,
                    "issuer_alternative_name": observable_data[
                        "issuer_alternative_name"
                    ]
                    if "issuer_alternative_name" in observable_data
                    else None,
                    "subject_directory_attributes": observable_data[
                        "subject_directory_attributes"
                    ]
                    if "subject_directory_attributes" in observable_data
                    else None,
                    "crl_distribution_points": observable_data[
                        "crl_distribution_points"
                    ]
                    if "crl_distribution_points" in observable_data
                    else None,
                    "inhibit_any_policy": observable_data["inhibit_any_policy"]
                    if "inhibit_any_policy" in observable_data
                    else None,
                    "private_key_usage_period_not_before": observable_data[
                        "private_key_usage_period_not_before"
                    ]
                    if "private_key_usage_period_not_before" in observable_data
                    else None,
                    "private_key_usage_period_not_after": observable_data[
                        "private_key_usage_period_not_after"
                    ]
                    if "private_key_usage_period_not_after" in observable_data
                    else None,
                    "certificate_policies": observable_data["certificate_policies"]
                    if "certificate_policies" in observable_data
                    else None,
                    "policy_mappings": observable_data["policy_mappings"]
                    if "policy_mappings" in observable_data
                    else None,
                }
            elif type == "X-OpenCTI-Cryptographic-Key":
                input_variables["XOpenCTICryptographicKey"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "X-OpenCTI-Cryptocurrency-Wallet":
                input_variables["XOpenCTICryptocurrencyWallet"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "X-OpenCTI-Hostname":
                input_variables["XOpenCTIHostname"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "X-OpenCTI-Text":
                input_variables["XOpenCTIText"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
                    else None,
                }
            elif type == "X-OpenCTI-User-Agent":
                input_variables["XOpenCTIUserAgent"] = {
                    "value": observable_data["value"]
                    if "value" in observable_data
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
        operation = kwargs.get("operation", "replace")

        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating Stix-Observable {" + id + "} field {" + key + "}."
            )
            query = """
                mutation StixCyberObservableEdit($id: ID!, $input: EditInput!, $operation: EditOperation) {
                    stixCyberObservableEdit(id: $id) {
                        fieldPatch(input: $input, operation: $operation) {
                            id
                            standard_id
                        }
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {"key": key, "value": value},
                    "operation": operation,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableEdit"]["fieldPatch"]
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
                     stixCyberObservableEdit(id: $id) {
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
        Update the Identity author of a Stix-Cyber-Observable object (created_by)

        :param id: the id of the Stix-Cyber-Observable
        :param identity_id: the id of the Identity
        :return Boolean
    """

    def update_created_by(self, **kwargs):
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Updating author of Stix-Cyber-Observable {"
                + id
                + "} with Identity {"
                + str(identity_id)
                + "}",
            )
            custom_attributes = """
                id
                createdBy {
                    ... on Identity {
                        id
                        standard_id
                        entity_type
                        parent_types
                        name
                        x_opencti_aliases
                        description
                        created
                        modified
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
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object["createdBy"] is not None:
                query = """
                    mutation StixCyberObservableEdit($id: ID!, $toId: String! $relationship_type: String!) {
                        stixCyberObservableEdit(id: $id) {
                            relationDelete(toId: $toId, relationship_type: $relationship_type) {
                                id
                            }
                        }
                    }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "toId": stix_domain_object["createdBy"]["id"],
                        "relationship_type": "created-by",
                    },
                )
            if identity_id is not None:
                # Add the new relation
                query = """
                    mutation StixCyberObservableEdit($id: ID!, $input: StixMetaRelationshipAddInput) {
                        stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                        }
                    }
               """
                variables = {
                    "id": id,
                    "input": {
                        "toId": identity_id,
                        "relationship_type": "created-by",
                    },
                }
                self.opencti.query(query, variables)
        else:
            self.opencti.log("error", "Missing parameters: id")
            return False

    """
        Add a Marking-Definition object to Stix-Cyber-Observable object (object_marking_refs)

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            custom_attributes = """
                id
                objectMarking {
                    edges {
                        node {
                            id
                            standard_id
                            entity_type
                            definition_type
                            definition
                            x_opencti_order
                            x_opencti_color
                            created
                            modified
                        }
                    }
                }
            """
            stix_cyber_observable = self.read(id=id, customAttributes=custom_attributes)
            if stix_cyber_observable is None:
                self.opencti.log(
                    "error", "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_cyber_observable["markingDefinitionsIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding Marking-Definition {"
                    + marking_definition_id
                    + "} to Stix-Cyber-Observable {"
                    + id
                    + "}",
                )
                query = """
                   mutation StixCyberObservableAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                       stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "toId": marking_definition_id,
                            "relationship_type": "object-marking",
                        },
                    },
                )
                return True
        else:
            self.opencti.log(
                "error", "Missing parameters: id and marking_definition_id"
            )
            return False

    """
        Remove a Marking-Definition object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def remove_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            self.opencti.log(
                "info",
                "Removing Marking-Definition {"
                + marking_definition_id
                + "} from Stix-Cyber-Observable {"
                + id
                + "}",
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": marking_definition_id,
                    "relationship_type": "object-marking",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def add_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters=[{"key": "value", "values": [label_name]}]
            )
            if label:
                label_id = label["id"]
            else:
                label = self.opencti.label.create(value=label_name)
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.log(
                "info",
                "Adding label {" + label_id + "} to Stix-Cyber-Observable {" + id + "}",
            )
            query = """
               mutation StixCyberObservableAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixCyberObservableEdit(id: $id) {
                        relationAdd(input: $input) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {
                        "toId": label_id,
                        "relationship_type": "object-label",
                    },
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Remove a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def remove_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters=[{"key": "value", "values": [label_name]}]
            )
            if label:
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.log(
                "info",
                "Removing label {"
                + label_id
                + "} to Stix-Cyber-Observable {"
                + id
                + "}",
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": label_id,
                    "relationship_type": "object-label",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a External-Reference object to Stix-Cyber-Observable object (object_marking_refs)

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            custom_attributes = """
                id
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
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object is None:
                self.opencti.log(
                    "error", "Cannot add External-Reference, entity not found"
                )
                return False
            if external_reference_id in stix_domain_object["externalReferencesIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding External-Reference {"
                    + external_reference_id
                    + "} to Stix-Cyber-Observable {"
                    + id
                    + "}",
                )
                query = """
                   mutation StixCyberObservabletEditRelationAdd($id: ID!, $input: StixMetaRelationshipAddInput) {
                       stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "toId": external_reference_id,
                            "relationship_type": "external-reference",
                        },
                    },
                )
                return True
        else:
            self.opencti.log(
                "error", "Missing parameters: id and external_reference_id"
            )
            return False

    """
        Remove a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def remove_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.log(
                "info",
                "Removing External-Reference {"
                + external_reference_id
                + "} to Stix-Cyber-Observable {"
                + id
                + "}",
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": external_reference_id,
                    "relationship_type": "external-reference",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    def push_list_export(self, file_name, data, list_filters=""):
        query = """
            mutation StixCyberObservablesExportPush($file: Upload!, $listFilters: String) {
                stixCyberObservablesExportPush(file: $file, listFilters: $listFilters)
            } 
        """
        self.opencti.query(
            query,
            {
                "file": (self.file(file_name, data)),
                "listFilters": list_filters,
            },
        )
