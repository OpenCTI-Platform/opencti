import gql from 'graphql-tag' ;

const typeDefs = gql`
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
        networkAdd(input: NetworkAddInput): Network
        networkDelete(id: String!): String!
        networkEdit(id: String!, input: [EditInput]!, commitMessage: String): Network
    }

    # Query Types
    "Defines identifying information about a network."
    type Network implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # Network
        network_id: String!
        network_name: String!
        network_address_range: IpAddressRange
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


    # Mutation Types
    input NetworkAddInput {
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

`;

export default typeDefs ;