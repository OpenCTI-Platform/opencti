import gql from 'graphql-tag' ;

const typeDefs = gql`
    # Query Extensions
    extend type Query {
        networkList(
            first: Int
            offset: Int
            orderedBy: NetworkOrdering
            orderMode: OrderingMode
            filters: [NetworkFiltering]
            filterMode: FilterMode
            search: String
         ): [Network]
        network(id: String!): Network
    }

    extend type Mutation {
        createNetwork(input: NetworkAddInput): Network
        deleteNetwork(id: String!): String!
        editNetwork(id: String!, input: [EditInput]!, commitMessage: String): Network
    }

    # Query Types
    "Defines identifying information about a network."
    type Network implements RootObject & CoreObject & Asset & ItAsset {
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
        # Network
        network_id: String!
        network_name: String!
        network_address_range: IpAddressRange
    }

    # Mutation Types
    input NetworkAddInput {
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
        # Network
        network_id: String!
        network_name: String!
        network_ipv4_address_range: IpV4AddressRangeAddInput
        network_ipv6_address_range: IpV6AddressRangeAddInput
    }

    input NetworkFiltering {
        key: NetworkFilter!
        values: [String]
        operator: String
        filterMode: FilterMode 
    }

    # Pagination Types
    type NetworkConnection {
        pageInfo: PageInfo!
        edges: [NetworkEdge]
    }

    type NetworkEdge {
        cursor: String!
        node: Network!
    }

    enum NetworkOrdering {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

    enum NetworkFilter {
        name
        asset_type
        asset_id
        ip_address
        installed_operating_system
        network_id
        labels
    }

`;

export default typeDefs ;