import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about a network device."
    type NetworkDevice implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a network appliance device."
    type Appliance implements BasicObject & ExternalObject & Asset & ItAsset  {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a network firewall device."
    type Firewall implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a network router device."
    type Router implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a storage array device."
    type StorageArray implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a network switch device."
    type Switch implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a Voice over IP handset or phone device."
    type VoIPHandset implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }

    "Defines identifying information about a VoIP router device."
    type VoIPRouter implements BasicObject & ExternalObject& Asset & ItAsset {
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
        # Hardware
        function: String
        cpe_identifier: String
        installation_id: String
        installed_hardware: [ComputingDevice!]!
        installed_operatingSystem: OperatingSystem!
        model: String
        motherboard_id: String
        baseline_configuration_name: String
        # Network Device
        connected_to_network: Network
        default_gateway: String
        ip_address: [IpAddress!]!
        mac_address: [MAC!]!
        vlan_id: String
        uri: String
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        is_virtual: Boolean
        ports: [PortInfo!]!
    }
`;

export default typeDefs ;
