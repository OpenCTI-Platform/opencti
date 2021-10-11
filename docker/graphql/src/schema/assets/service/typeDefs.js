import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about an instance of service."
    type Service implements RootObject & CoreObject & Asset & ItAsset {
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
        # Service
        function: String
        service_software: Software
        ip_address: [IpAddress!]!
        is_publicly_accessible: Boolean
        is_scanned: Boolean
        ports: [PortInfo!]!
    }
`;

export default typeDefs ;