SCO_PROPERTIES = """
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
    creators {
        id
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
     ... on SSHKey {
        key_type
        public_key
        fingerprint_sha256
        fingerprint_md5
        key_length
        expiration_date
        comment
        created
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
        x_opencti_product
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
    ... on Persona {
        persona_name
        persona_type
    }
    ... on MediaContent {
        title
        content
        media_category
        url
        publication_date
    }
    ... on IMEI {
        value
    }
    ... on ICCID {
        value
    }
    ... on IMSI {
        value
    }
"""
SCO_PROPERTIES_WITH_FILES = """
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
    creators {
        id
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
    ... on SSHKey {
        key_type
        public_key
        fingerprint_sha256
        fingerprint_md5
        key_length
        expiration_date
        comment
        created
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
        x_opencti_product
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
    ... on Persona {
        persona_name
        persona_type
    }
    ... on MediaContent {
        title
        content
        media_category
        url
        publication_date
    }
    ... on IMEI {
        value
    }
    ... on ICCID {
        value
    }
    ... on IMSI {
        value
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
"""
