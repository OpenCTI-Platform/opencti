import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about an instance of electronic collection of data, or information, that is specially organized for rapid search and retrieval."
    type Database implements BasicObject & ExternalObject & Asset & ItAsset {
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
        # database
        instance_name: String!
        served_by: Service
    }
`;

export default typeDefs ;
