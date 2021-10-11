import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about an instance of electronic collection of data, or information, that is specially organized for rapid search and retrieval."
    type Database implements RootObject & CoreObject & Asset & ItAsset {
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
        # database
        instance_name: String!
        served_by: Service
    }
`;

export default typeDefs ;
