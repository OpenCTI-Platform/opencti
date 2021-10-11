import gql from 'graphql-tag' ;

const typeDefs = gql`
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
        addComputingDevice(input: ComputingDeviceAddInput): ComputingDevice
        deleteComputingDevice(id: String!): String!
        editComputingDevice(id: String!, input: [EditInput]!, commitMessage: String): ComputingDevice
    }

    "Defines identifying information about a network."
    type ComputingDevice implements RootObject & CoreObject & Asset & ItAsset {
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
    type Server implements RootObject & CoreObject & Asset & ItAsset {
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
    type Workstation implements RootObject & CoreObject & Asset & ItAsset {
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

    # Mutation Types
    input ComputingDeviceAddInput {
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
        # responsible_parties: [ResponsibleParty]
        # Hardware
        cpe_identifier: String
        installation_id: String
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        function: String
        # Computing Device
        bios_id: String
        default_gateway: String
        fqdn: String
        hostname: String
        netbios_name: String
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

    # Pagination Types
    type ComputingDeviceConnection {
        pageInfo: PageInfo!
        edges: [ComputingDeviceEdge]
    }

    type ComputingDeviceEdge {
        cursor: String!
        node: ComputingDevice!
    }

`;

export default typeDefs ;
