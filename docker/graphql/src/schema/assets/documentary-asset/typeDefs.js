import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about any guideline or recommendation."
    type Guidance implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

    "Defines identifying information about an applicable plan."
    type Plan implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

    "Defines identifying information about an enforceable policy."
    type Policy implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

    "Defines identifying information about a list of steps or actions to take to achieve some end result."
    type Procedure implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

    "Defines identifying information about any organizational or industry standard."
    type Standard implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

    "Defines identifying information about an external assessment performed on some other component, that has been validated by a third-party."
    type Validation implements BasicObject & ExternalObject & Asset & ItAsset & DocumentaryAsset {
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
    }

`;

export default typeDefs ;