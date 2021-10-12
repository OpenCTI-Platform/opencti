import gql from 'graphql-tag' ;

const typeDefs = gql`
    "Defines identifying information about any guideline or recommendation."
    type Guidance implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

    "Defines identifying information about an applicable plan."
    type Plan implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

    "Defines identifying information about an enforceable policy."
    type Policy implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

    "Defines identifying information about a list of steps or actions to take to achieve some end result."
    type Procedure implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

    "Defines identifying information about any organizational or industry standard."
    type Standard implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

    "Defines identifying information about an external assessment performed on some other component, that has been validated by a third-party."
    type Validation implements RootObject & CoreObject & Asset & ItAsset & DocumentaryAsset {
        # Root Object
        id: String!
        entity_type: String!
        # CoreObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references( first: Int ): ExternalReferenceConnection
        notes( first: Int ): NoteConnection
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
    }

`;

export default typeDefs ;