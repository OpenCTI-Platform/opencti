import gql from 'graphql-tag' ;

const typeDefs = gql`
    enum ComputingDeviceOrdering {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

    enum ComputingDeviceFilter {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

    input ComputingDeviceFiltering {
        key: ComputingDeviceFilter!
        values: [String]
        operator: String
        filterMode: FilterMode 
    }

    # Mutation Types
    input ComputingDeviceAddInput {
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
        locations: [AssetLocationAddInput]!
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
        # Computing Device
        bios_id: String
        connected_to_network: NetworkAddInput
        default_gateway: String
        fqdn: String
        hostname: String
        netbios_name: String
        installed_software: [SoftwareAddInput!]!
        ipv4_address: [IpV4AddressAddInput]!
        ipv6_address: [IpV6AddressAddInput]!
        mac_address: [MAC!]!
        network_id: String
        vlan_id: String
        uri: URL
        ports: [PortInfoAddInput!]!
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    # Pagination Types
    type ComputingDeviceConnection {
        pageInfo: PageInfo!
        edges: [ComputingDeviceEdge]
    }

    type ComputingDeviceEdge {
        cursor: String!
        node: ComputingDevice!
    }

    extend type Query {
        computingDeviceList(
            first: Int
            offset: Int
            orderedBy: ComputingDeviceOrdering
            orderMode: OrderingMode
            filters: [ComputingDeviceFiltering]
            filterMode: FilterMode
            search: String
         ): [ComputingDevice]
        computingDevice(id: String!): ComputingDevice
    }

    extend type Mutation {
        computingDeviceAdd(input: ComputingDeviceAddInput): ComputingDevice
        computingDeviceDelete(id: String!): String!
        computingDeviceEdit(id: String!, input: [EditInput]!, commitMessage: String): ComputingDevice
    }

    "Defines identifying information about a network."
    type ComputingDevice implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Computing Device
        bios_id: String
        connected_to_network: Network
        default_gateway: String
        fqdn: String
        hostname: String
        netbios_name: String
        installed_software: [Software!]!
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        network_id: String
        vlan_id: String
        uri: URL
        ports: [PortInfo!]!
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about infrastructure server device that perform generic computing capabilities."
    type Server implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Computing Device
        bios_id: String
        connected_to_network: Network
        default_gateway: String
        fqdn: String
        hostname: String
        netbios_name: String
        installed_software: [Software!]!
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        ports: [PortInfo!]!
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }

    "Defines identifying information about a workstation that perform generic computing capabilities."
    type Workstation implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Computing Device
        bios_id: String
        connected_to_network: Network
        default_gateway: String
        fqdn: String
        hostname: String
        netbios_name: String
        installed_software: [Software!]!
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        ports: [PortInfo!]!
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
    }
`;

export default typeDefs ;
