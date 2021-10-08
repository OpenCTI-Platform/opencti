import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about an instance of an information system."
    type System implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        labels: [String]
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
    type DirectoryServer implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        labels: [String]
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
    type DnsServer implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        labels: [String]
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
    type EmailServer implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        labels: [String]
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
    type WebServer implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        labels: [String]
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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