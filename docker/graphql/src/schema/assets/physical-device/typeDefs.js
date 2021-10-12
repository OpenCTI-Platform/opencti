import gql from 'graphql-tag' ;

const typeDefs = gql`
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
    type Physical implements RootObject & CoreObject & Asset & ItAsset & Hardware {
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

    # Mutation Types
    input PhysicalDeviceAddInput {
        labels: [String]
        # Asset
        asset_id: String
        name: String!
        description: String
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Hardware
        cpe_identifier: String
        installation_id: String
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

    # Pagination Types
    type PhysicalDeviceConnection {
        pageInfo: PageInfo!
        edges: [PhysicalDeviceEdge]
    }

    type PhysicalDeviceEdge {
        cursor: String!
        node: PhysicalDevice!
    }

`;

export default typeDefs ;