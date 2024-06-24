# coding: utf-8
import json


class StixCoreObject:
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
            objectOrganization {
                id
                standard_id
                name
            }
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
                    }
                }
            }
            ... on StixDomainObject {
                revoked
                confidence
                created
                modified
            }
            ... on AttackPattern {
                name
                description
                aliases
                x_mitre_platforms
                x_mitre_permissions_required
                x_mitre_detection
                x_mitre_id
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on Campaign {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Note {
                attribute_abstract
                content
                authors
                note_types
                likelihood
            }
            ... on ObservedData {
                first_observed
                last_observed
                number_observed
            }
            ... on Opinion {
                explanation
                authors
                opinion
            }
            ... on Report {
                name
                description
                report_types
                published
            }
            ... on Grouping {
                name
                description
                context
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on CourseOfAction {
                name
                description
                x_opencti_aliases
            }
            ... on DataComponent {
                name
                description
                dataSource {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    created_at
                    updated_at
                    revoked
                    confidence
                    created
                    modified
                    name
                    description
                    x_mitre_platforms
                    collection_layers
                }
            }
            ... on DataSource {
                name
                description
                x_mitre_platforms
                collection_layers
            }
            ... on Individual {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Sector {
                name
                description
                contact_information
                x_opencti_aliases
            }
            ... on System {
                name
                description
                contact_information
                x_opencti_aliases
            }
            ... on Indicator {
                pattern_type
                pattern_version
                pattern
                name
                description
                indicator_types
                valid_from
                valid_until
                x_opencti_score
                x_opencti_detection
                x_opencti_main_observable_type
            }
            ... on Infrastructure {
                name
                description
                aliases
                infrastructure_types
                first_seen
                last_seen
            }
            ... on IntrusionSet {
                name
                description
                aliases
                first_seen
                last_seen
                goals
                resource_level
                primary_motivation
                secondary_motivations
            }
            ... on City {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Country {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Region {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Position {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
                street_address
                postal_code
            }
            ... on Malware {
                name
                description
                aliases
                malware_types
                is_family
                first_seen
                last_seen
                architecture_execution_envs
                implementation_languages
                capabilities
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on MalwareAnalysis {
                product
                version
                configuration_version
                modules
                analysis_engine_version
                analysis_definition_version
                submitted
                analysis_started
                analysis_ended
                result_name
                result
            }
            ... on ThreatActor {
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
                personal_motivations
            }
            ... on Tool {
                name
                description
                aliases
                tool_types
                tool_version
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on Vulnerability {
                name
                description
                x_opencti_cvss_base_score
                x_opencti_cvss_base_severity
                x_opencti_cvss_attack_vector
                x_opencti_cvss_integrity_impact
                x_opencti_cvss_availability_impact
            }
            ... on Incident {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Event {
                name
                description
            }
            ... on Channel {
                name
                description
                aliases
                channel_types
            }
            ... on Narrative {
                name
                description
                aliases
                narrative_types
            }
            ... on DataComponent {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on Case {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Feedback {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on StixCyberObservable {
                observable_value
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
            ... on AutonomousSystem {
                number
                name_alt: name
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
                importFiles {
                    edges {
                        node {
                            id
                            name
                            size
                        }
                    }
                }
            }
            ... on StixFile {
                extensions
                size
                name_alt: name
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
                name_alt: name
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
                name_alt: name
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
                name_alt: name
                data
                data_type
            }
            ... on CryptographicKey {
                value
            }
            ... on CryptocurrencyWallet {
                value
            }
            ... on Hostname {
                value
            }
            ... on Text {
                value
            }
            ... on UserAgent {
                value
            }
            ... on BankAccount {
                iban
                bic
                account_number
            }
            ... on PhoneNumber {
                value
            }
            ... on TrackingNumber {
                value
            }
            ... on Credential {
                value
            }
            ... on PaymentCard {
                card_number
                expiration_date
                cvv
                holder_name
            }
            ... on MediaContent {
                title
                content_alt: content
                media_category
                url
                publication_date
            }
        """
        self.properties_with_files = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            objectOrganization {
                id
                standard_id
                name
            }
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
            ... on StixDomainObject {
                revoked
                confidence
                created
                modified
            }
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
            ... on AttackPattern {
                name
                description
                aliases
                x_mitre_platforms
                x_mitre_permissions_required
                x_mitre_detection
                x_mitre_id
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on Campaign {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Note {
                attribute_abstract
                content
                authors
                note_types
                likelihood
            }
            ... on ObservedData {
                first_observed
                last_observed
                number_observed
            }
            ... on Opinion {
                explanation
                authors
                opinion
            }
            ... on Report {
                name
                description
                report_types
                published
            }
            ... on Grouping {
                name
                description
                context
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on CourseOfAction {
                name
                description
                x_opencti_aliases
            }
            ... on DataComponent {
                name
                description
                dataSource {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    created_at
                    updated_at
                    revoked
                    confidence
                    created
                    modified
                    name
                    description
                    x_mitre_platforms
                    collection_layers
                }
            }
            ... on DataSource {
                name
                description
                x_mitre_platforms
                collection_layers
            }
            ... on Individual {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Sector {
                name
                description
                contact_information
                x_opencti_aliases
            }
            ... on System {
                name
                description
                contact_information
                x_opencti_aliases
            }
            ... on Indicator {
                pattern_type
                pattern_version
                pattern
                name
                description
                indicator_types
                valid_from
                valid_until
                x_opencti_score
                x_opencti_detection
                x_opencti_main_observable_type
            }
            ... on Infrastructure {
                name
                description
                aliases
                infrastructure_types
                first_seen
                last_seen
            }
            ... on IntrusionSet {
                name
                description
                aliases
                first_seen
                last_seen
                goals
                resource_level
                primary_motivation
                secondary_motivations
            }
            ... on City {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Country {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Region {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Position {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
                street_address
                postal_code
            }
            ... on Malware {
                name
                description
                aliases
                malware_types
                is_family
                first_seen
                last_seen
                architecture_execution_envs
                implementation_languages
                capabilities
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on MalwareAnalysis {
                product
                version
                configuration_version
                modules
                analysis_engine_version
                analysis_definition_version
                submitted
                analysis_started
                analysis_ended
                result_name
                result
            }
            ... on ThreatActor {
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
                personal_motivations
            }
            ... on Tool {
                name
                description
                aliases
                tool_types
                tool_version
                killChainPhases {
                  id
                  standard_id
                  entity_type
                  kill_chain_name
                  phase_name
                  x_opencti_order
                  created
                  modified
                }
            }
            ... on Vulnerability {
                name
                description
                x_opencti_cvss_base_score
                x_opencti_cvss_base_severity
                x_opencti_cvss_attack_vector
                x_opencti_cvss_integrity_impact
                x_opencti_cvss_availability_impact
            }
            ... on Incident {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Event {
                name
                description
            }
            ... on Channel {
                name
                description
                aliases
                channel_types
            }
            ... on Narrative {
                name
                description
                aliases
                narrative_types
            }
            ... on DataComponent {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on Case {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Feedback {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on StixCyberObservable {
                observable_value
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
            ... on AutonomousSystem {
                number
                name_alt: name
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
                importFiles {
                    edges {
                        node {
                            id
                            name
                            size
                        }
                    }
                }
            }
            ... on StixFile {
                extensions
                size
                name_alt: name
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
                name_alt: name
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
                name_alt: name
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
                name_alt: name
                data
                data_type
            }
            ... on CryptographicKey {
                value
            }
            ... on CryptocurrencyWallet {
                value
            }
            ... on Hostname {
                value
            }
            ... on Text {
                value
            }
            ... on UserAgent {
                value
            }
            ... on BankAccount {
                iban
                bic
                account_number
            }
            ... on PhoneNumber {
                value
            }
            ... on PaymentCard {
                card_number
                expiration_date
                cvv
                holder_name
            }
            ... on MediaContent {
                title
                content_alt: content
                media_category
                url
                publication_date
            }
        """

    """
        List Stix-Core-Object objects

        :param types: the list of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Stix-Core-Object objects
    """

    def list(self, **kwargs):
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)
        if get_all:
            first = 100

        self.opencti.app_logger.info(
            "Listing Stix-Core-Objects with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                    query StixCoreObjects($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: StixCoreObjectsOrdering, $orderMode: OrderingMode) {
                        stixCoreObjects(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                            edges {
                                node {
                                    """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
            )
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
            data = self.opencti.process_multiple(result["data"]["stixCoreObjects"])
            final_data = final_data + data
            while result["data"]["stixCoreObjects"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixCoreObjects"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing Stix-Core-Objects", {"after": after}
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
                data = self.opencti.process_multiple(result["data"]["stixCoreObjects"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixCoreObjects"], with_pagination
            )

    """
            Read a Stix-Core-Object object

            :param id: the id of the Stix-Core-Object
            :param types: list of Stix Core Entity types
            :param filters: the filters to apply if no id provided
            :return Stix-Core-Object object
        """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Stix-Core-Object", {"id": id})
            query = (
                """
                        query StixCoreObject($id: String!) {
                            stixCoreObject(id: $id) {
                                """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                        }
                    }
                 """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["stixCoreObject"]
            )
        elif filters is not None:
            result = self.list(
                types=types, filters=filters, customAttributes=custom_attributes
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_core_object] Missing parameters: id or filters"
            )
            return None

    def list_files(self, **kwargs):
        id = kwargs.get("id", None)
        self.opencti.app_logger.info("Listing files of Stix-Core-Object", {"id": id})
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

    def push_list_export(
        self,
        entity_id,
        entity_type,
        file_name,
        file_markings,
        data,
        list_filters="",
        mime_type=None,
    ):
        query = """
            mutation StixCoreObjectsExportPush($entity_id: String, $entity_type: String!, $file: Upload!, $file_markings: [String]!, $listFilters: String) {
                stixCoreObjectsExportPush(entity_id: $entity_id, entity_type: $entity_type, file: $file, file_markings: $file_markings, listFilters: $listFilters)
            }
        """

        if mime_type is None:
            file = self.file(file_name, data)
        else:
            file = self.file(file_name, data, mime_type)
        self.opencti.query(
            query,
            {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "file": file,
                "file_markings": file_markings,
                "listFilters": list_filters,
            },
        )

    def push_analysis(
        self,
        entity_id,
        file_name,
        data,
        content_source,
        content_type,
        analysis_type,
    ):
        query = """
            mutation StixCoreObjectEdit(
                $id: ID!, $file: Upload!, $contentSource: String!, $contentType: AnalysisContentType!, $analysisType: String!
            ) {
                stixCoreObjectEdit(id: $id) {
                    analysisPush(file: $file,contentSource: $contentSource,contentType: $contentType,analysisType: $analysisType){
                        id
                        name
                    }
                }
            }
        """

        file = self.file(file_name, data)
        self.opencti.query(
            query,
            {
                "id": entity_id,
                "file": file,
                "contentSource": content_source,
                "contentType": content_type,
                "analysisType": analysis_type,
            },
        )

    """
        Get the reports about a Stix-Core-Object object

        :param id: the id of the Stix-Core-Object
        :return List of reports
    """

    def reports(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting reports of the Stix-Core-Object", {"id": id}
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
            self.opencti.app_logger.error("Missing parameters: id")
            return None
