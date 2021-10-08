import gql from 'graphql-tag' ;

const typeDefs = gql`
    enum PhysicalDeviceOrdering {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

    enum PhysicalDeviceFilter {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

    # Query Extensions
    extend type Query {
        physicalDeviceList(
            first: Int
            offset: Int
            orderedBy: PhysicalDeviceOrdering
            orderMode: OrderingMode
            filters: [PhysicalDeviceFiltering]
            filterMode: FilterMode
            search: String
         ): [PhysicalDevice]
        physicalDevice(id: String!): PhysicalDevice
    }

    extend type Mutation {
        physicalDeviceAdd(input: PhysicalDeviceAddInput): PhysicalDevice
        physicalDeviceDelete(id: String!): String!
        physicalDeviceEdit(id: String!, input: [EditInput]!, commitMessage: String): PhysicalDevice
    }

    # Query Types
    "Defines identifying information about a network."
    type Physical implements BasicObject & ExternalObject & Asset & ItAsset & Hardware {
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
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Hardware
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operating_system: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        function: String
        # PhysicalDevice
    }

    # Pagination Types
    type PhysicalDeviceConnection {
        pageInfo: PageInfo!
        edges: [PhysicalDeviceEdge]
    }

    type PhysicalDeviceEdge {
        cursor: String!
        node: PhysicalDevice!
    }

    # Mutation Types
    input PhysicalDeviceAddInput {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReferenceAddInput]
        notes: [NoteAddInput]
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
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Hardware
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDeviceAddInput!]!
        installed_operating_system: OperatingSystemAddInput!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        function: String
        # PhysicalDevice
    }

    input PhysicalDeviceFiltering {
        key: PhysicalDeviceFilter!
        values: [String]
        operator: String
        filterMode: FilterMode 
    }

`;

export default typeDefs ;