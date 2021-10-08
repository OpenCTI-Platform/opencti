import gql from 'graphql-tag' ;

const typeDefs = gql`
    # ENUMERATIONS

    "Defines the types of assets."
    enum AssetType {
        operating_system
        database
        web_server
        dns_server
        email_server
        directory_server
        pbx
        firewall
        router
        switch
        storage_array
        appliance
        application_software
        network_device
        circuit
        compute_device
        workstation
        server
        network
        service
        software
        physical_device
        system
        web_site
        voip_handset
        voip_router
    }

    "Defines network protocols"
    enum NetworkProtocol {
        TCP
        UDP
        ICMP
        TLS
        SSL
        DHCP
        DNS
        HTTP
        HTTPS
        NFS
        POP3
        SMTP
        SNMP
        FTP
        NTP
        IRC
        Telnet
        SSH
        TFTP
        IMAP
        ARP
        NetBIOS
        SOAP
        IP
        IPSEC
        IPX
        NAT
        OSPF
        RDP
        RIP
        RPC
        SPX
        SMB
        SOCKS
    }

    type AssetLocation implements BasicObject & ExternalObject & Location {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReference]
      notes: [Note]
      # Location
      name: String!
      description: String
      # Asset Location
      street_address: String
      city: String
      administrative_area: String
      country: String
      postal_code: PostalCode
    }
    
    input AssetLocationAddInput {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReferenceAddInput]
      notes: [NoteAddInput]
      # Location
      name: String!
      description: String
      # Asset Location
      street_address: String
      city: String
      administrative_area: String
      country: String
      postal_code: PostalCode
    }

    "An abstract interface that defines identifying information about an asset in it generic form as something of value."
    interface Asset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        #Asset
        asset_id: String
        description: String
        name: String!
        locations: [Location]
    }

    "An abstract interface that defines identifying information about an asset that is technology-based, such as hardware, software, and networking."
    interface ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # ItAsset
        asset_tag: String
        asset_type: AssetType!
        operational_status: OperationalStatus!
        release_date: DateTime
        serial_number: String
        vendor_name: String
        version: String
    }

    "An abstract interface that defines identifying information about a documentary asset, such as policies, procedures."
    interface DocumentaryAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # DocumentaryAsset
        release_date: DateTime!
    }

    "An abstract interface that defines identifying information about an instance of data."
    interface Data {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Data
    }

    interface Hardware {
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
    }

    "Captures identifying information about an account.  The Account class is an extension to NIST-7693 that was \\\"missing\\\". The relationship with other Account classes from other ontologies will likely be established here."
    interface Account {
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
        # IT Asset
        asset_tag: String
        asset_type: AssetType!
        operational_status: OperationalStatus!
        release_date: DateTime
        serial_number: String
        vendor_name: String
        version: String
    }

    type IpAddressRange {
        starting_ip_address: IpAddress!
        ending_ip_address: IpAddress!
    }

    input IpV4AddressRangeAddInput {
        starting_ip_address: IpV4AddressAddInput!
        ending_ip_address: IpV4AddressAddInput!
    }

    input IpV6AddressRangeAddInput {
        starting_ip_address: IpV6AddressAddInput!
        ending_ip_address: IpV6AddressAddInput!
    }

    interface IpAddress {
        id: String!
        object_type: String!
    }

    type IpV4Address implements BasicObject & IpAddress {
        id: String!
        object_type: String!
        # IpV4Address
        ip_address_value: IPv4!
    }

    type IpV6Address implements BasicObject & IpAddress {
        id: String!
        object_type: String!
        # IpV6Address
        ip_address_value: IPv6!
    }

    input IpV4AddressAddInput {
        id: String!
        object_type: String!
        # IpV4Address
        ip_address_value: IPv4!
   } 

    input IpV6AddressAddInput {
        id: String!
        object_type: String!
        # IpV6Address
        ip_address_value: IPv6!
    }

    "Defines identifying information about a network port."
    type PortInfo {
        port_number: Port
        protocols: NetworkProtocol
    }

    input PortInfoAddInput {
        port_number: Port
        protocols: NetworkProtocol
    }

    type StartEndPortRange {
        starting_port: Port
        ending_port: Port
        protocols: NetworkProtocol
    }
    
    union PortRange = PortInfo | StartEndPortRange
`;

export default typeDefs ;