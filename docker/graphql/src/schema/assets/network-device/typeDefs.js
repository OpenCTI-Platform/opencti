import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about a network device."
    type NetworkDevice implements RootObject & CoreObject & Asset & ItAsset {
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
    type Appliance implements RootObject & CoreObject & Asset & ItAsset  {
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
    type Firewall implements RootObject & CoreObject & Asset & ItAsset {
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
    type Router implements RootObject & CoreObject & Asset & ItAsset {
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
    type StorageArray implements RootObject & CoreObject & Asset & ItAsset {
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
    type Switch implements RootObject & CoreObject & Asset & ItAsset {
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
    type VoIPHandset implements RootObject & CoreObject & Asset & ItAsset {
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
    type VoIPRouter implements RootObject & CoreObject& Asset & ItAsset {
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
