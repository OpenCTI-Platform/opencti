import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about an instance of an information system."
    type System implements RootObject & CoreObject & Asset & ItAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        locations: [Location]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # responsible_parties: [ResponsibleParty]
        # System
        system_name: String
        function: String
        baseline_configuration_name: String
        connected_to_network: Network
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about an instance of a system that stores, organizes and provides access to directory information in order to unify network resources."
    type DirectoryServer implements RootObject & CoreObject & Asset & ItAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        locations: [Location]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # responsible_parties: [ResponsibleParty]
        # System
        system_name: String
        function: String
        baseline_configuration_name: String
        connected_to_network: Network
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about an instance of a system that resolves domain names to internet protocol (IP) addresses."
    type DnsServer implements RootObject & CoreObject & Asset & ItAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        locations: [Location]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # responsible_parties: [ResponsibleParty]
        # System
        system_name: String
        function: String
        baseline_configuration_name: String
        connected_to_network: Network
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about an instance of a system that sends and receives electronic mail messages."
    type EmailServer implements RootObject & CoreObject & Asset & ItAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        locations: [Location]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # responsible_parties: [ResponsibleParty]
        # System
        system_name: String
        function: String
        baseline_configuration_name: String
        connected_to_network: Network
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about an instance of a system that delivers content or services to end users over the Internet or an intranet."
    type WebServer implements RootObject & CoreObject & Asset & ItAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        locations: [Location]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # responsible_parties: [ResponsibleParty]
        # System
        system_name: String
        function: String
        baseline_configuration_name: String
        connected_to_network: Network
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }
`;

export default typeDefs ;